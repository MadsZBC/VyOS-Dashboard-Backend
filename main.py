from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Header, Security, UploadFile, File
from fastapi.security.api_key import APIKeyHeader, APIKey
from pydantic import BaseModel
from typing import Optional, Dict, Any, List, Union
import netmiko
from dotenv import load_dotenv
import os
import json
import re
import time
import asyncio
import subprocess
from datetime import datetime, timedelta
import secrets
import hashlib
from pathlib import Path
import tempfile
import uuid
import logging
from fastapi.middleware.cors import CORSMiddleware
import traceback

# Load environment variables from .env file
print("Loading environment variables...")
load_dotenv()

# Load configuration from environment variables
DEPLOYMENT_MODE = os.getenv("DEPLOYMENT_MODE", "remote").lower()
if DEPLOYMENT_MODE not in ["direct", "remote"]:
    print(f"Invalid DEPLOYMENT_MODE: {DEPLOYMENT_MODE}, defaulting to 'remote'")
    DEPLOYMENT_MODE = "remote"

# VyOS local configuration
VYOS_CONFIG_PATH = os.getenv("VYOS_CONFIG_PATH", "/config")
VYOS_DHCP_LEASES_FILE = os.getenv("VYOS_DHCP_LEASES_FILE", f"{VYOS_CONFIG_PATH}/dhcpd.leases")

# Connection cache settings
CONNECTION_CACHE_TTL = int(os.getenv("CONNECTION_CACHE_TTL", "300"))  # 5 minutes default

# Server settings
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8000"))

# Add to the top section with other constants
TEMP_KEY_DIR = os.getenv("TEMP_KEY_DIR", "./temp_keys")
KEY_EXPIRY_SECONDS = int(os.getenv("KEY_EXPIRY_SECONDS", "300"))  # 5 minutes default
SSH_KEYS_DIR = os.getenv("SSH_KEYS_DIR", "./ssh_keys")  # Persistent SSH keys directory

# Make sure directories exist
Path(TEMP_KEY_DIR).mkdir(exist_ok=True)
Path(SSH_KEYS_DIR).mkdir(exist_ok=True)
os.chmod(SSH_KEYS_DIR, 0o700)  # Secure permissions for SSH keys directory

print(f"Starting VyOS Router Manager API in {DEPLOYMENT_MODE.upper()} mode")
print(f"Server will listen on {HOST}:{PORT}")

app = FastAPI(title="VyOS Router Manager API")

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger("vyos_router_manager")

# Setup CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Update this with your frontend URLs in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API Key settings
API_KEY_NAME = "X-API-Key"
API_KEY_HEADER = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

# In-memory API key storage
# Format: {"hashed_key": {"name": "key_name", "created_at": datetime}}
api_keys = {}

# Temporary key storage - in memory mapping of key_id to file path and expiry time
temp_keys = {}

# Persistent SSH key storage
# Format: {"key_id": {"name": "key_name", "path": "/path/to/file", "created_at": datetime}}
ssh_keys = {}

# Load API keys from environment variable
if os.getenv("API_KEYS"):
    print("Loading API keys from environment variables...")
    env_keys_added = 0
    for key_entry in os.getenv("API_KEYS").split(','):
        try:
            name, api_key = key_entry.split(':')
            hashed_key = hashlib.sha256(api_key.encode()).hexdigest()
            api_keys[hashed_key] = {"name": name, "created_at": datetime.now()}
            env_keys_added += 1
            print(f"Added API key: {name}")
        except ValueError:
            print(f"Invalid API key format in environment variable: {key_entry}")
    
    print(f"Loaded {env_keys_added} API keys from environment variables")
else:
    print("No API keys found in environment variables")

# If no keys are loaded, create a default key
if not api_keys:
    default_key = secrets.token_urlsafe(32)
    hashed_key = hashlib.sha256(default_key.encode()).hexdigest()
    api_keys[hashed_key] = {"name": "default", "created_at": datetime.now()}
    print(f"Generated default API key: {default_key}")
    print("Store this key securely, it won't be shown again.")
    print("Add it to your .env file as API_KEYS=default:" + default_key)

def get_api_key(api_key_header: str = Security(API_KEY_HEADER)):
    if api_key_header is None:
        raise HTTPException(
            status_code=403,
            detail="Could not validate API key",
        )
    
    hashed_key = hashlib.sha256(api_key_header.encode()).hexdigest()
    if hashed_key not in api_keys:
        raise HTTPException(
            status_code=403,
            detail="Invalid API key",
        )
    
    return api_key_header

class VyOSConnection(BaseModel):
    host: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    port: Optional[int] = 22
    device_type: str = "vyos"
    use_keys: Optional[bool] = False
    key_file: Optional[str] = None
    passphrase: Optional[str] = None
    ssh_key_id: Optional[str] = None  # New field to specify a registered SSH key by ID
    ssh_key_name: Optional[str] = None  # New field to specify a registered SSH key by name

class RouterConfig(BaseModel):
    name: str
    host: str
    username: str
    password: str
    port: int = 22

class VyOSResponse(BaseModel):
    success: bool
    data: Dict[str, Any]
    message: str

class APIKeyResponse(BaseModel):
    key_name: str
    created_at: datetime

class NewAPIKey(BaseModel):
    name: str

class SSHKeyUpload(BaseModel):
    key_content: str
    key_name: Optional[str] = None

class RegisteredSSHKey(BaseModel):
    id: str
    name: str
    created_at: datetime

class NewSSHKey(BaseModel):
    name: str
    key_content: str

# Local system command execution for direct mode
def execute_local_command(command):
    """Execute a command directly on the VyOS system"""
    try:
        result = subprocess.run(
            command, 
            shell=True, 
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        raise Exception(f"Command failed with error: {e.stderr}")

# API Key management endpoints
@app.post("/api-keys/generate", response_model=Dict[str, str])
async def generate_api_key(new_key: NewAPIKey, api_key: APIKey = Depends(get_api_key)):
    """Generate a new API key with the given name"""
    api_key_value = secrets.token_urlsafe(32)
    hashed_key = hashlib.sha256(api_key_value.encode()).hexdigest()
    api_keys[hashed_key] = {"name": new_key.name, "created_at": datetime.now()}
    
    print(f"Generated new API key with name: {new_key.name}")
    print("Reminder: API keys are stored in memory and will be lost when the server restarts.")
    print("To make keys persistent, add them to your .env file as:")
    print(f"API_KEYS=...existing keys...,{new_key.name}:{api_key_value}")
    
    return {"name": new_key.name, "api_key": api_key_value}

@app.get("/api-keys/list", response_model=List[APIKeyResponse])
async def list_api_keys(api_key: APIKey = Depends(get_api_key)):
    """List all API keys (without revealing the actual keys)"""
    return [
        APIKeyResponse(key_name=info["name"], created_at=info["created_at"])
        for info in api_keys.values()
    ]

@app.delete("/api-keys/{key_name}", response_model=Dict[str, str])
async def delete_api_key(key_name: str, api_key: APIKey = Depends(get_api_key)):
    """Delete an API key by name"""
    # Find keys with the specified name
    keys_to_delete = [
        key for key, info in api_keys.items() if info["name"] == key_name
    ]
    
    if not keys_to_delete:
        raise HTTPException(status_code=404, detail=f"API key with name {key_name} not found")
    
    # Delete the keys
    for key in keys_to_delete:
        del api_keys[key]
    
    print(f"Deleted API key: {key_name}")
    print("Reminder: This change is in memory only. If the key is in your .env file,")
    print("you should remove it there to prevent it from being reloaded on restart.")
    
    return {"message": f"API key {key_name} deleted successfully"}

# Connection cache to reuse SSH connections
connection_cache = {}

def get_cached_connection(connection: VyOSConnection):
    """Try to get a cached connection or create a new one"""
    # For key-based authentication, include key file in cache key
    if connection.use_keys:
        cache_key = f"{connection.username}@{connection.host}:{connection.port}:keyfile={connection.key_file}"
    else:
        cache_key = f"{connection.username}@{connection.host}:{connection.port}"
    
    logger.debug(f"Connection request: {cache_key}")
    
    # Check if we have a valid cached connection
    if cache_key in connection_cache:
        cached_conn = connection_cache[cache_key]
        if cached_conn['expires'] > datetime.now() and cached_conn['connection'].is_alive():
            # Update expiration time
            cached_conn['expires'] = datetime.now() + timedelta(seconds=CONNECTION_CACHE_TTL)
            logger.debug(f"Using cached connection for {cache_key}")
            return cached_conn['connection']
        else:
            logger.debug(f"Cached connection expired or not alive for {cache_key}")
    
    # Create a new connection
    device = {
        'device_type': connection.device_type,
        'host': connection.host,
        'username': connection.username,
        'port': connection.port,
        'verbose': False,  # Reduce verbosity for better performance
        'global_delay_factor': 1,  # Reduced from 2 to 1 for better performance
    }
    
    # Add authentication method based on parameters
    if connection.use_keys:
        device['use_keys'] = True
        
        logger.debug(f"Using key-based authentication for {connection.username}@{connection.host}")
        
        # Check if using registered SSH key
        if connection.ssh_key_id:
            if connection.ssh_key_id not in ssh_keys:
                logger.error(f"SSH key ID not found: {connection.ssh_key_id}")
                raise HTTPException(
                    status_code=400, 
                    detail=f"SSH key with ID {connection.ssh_key_id} not found"
                )
            device['key_file'] = ssh_keys[connection.ssh_key_id]["path"]
            logger.debug(f"Using registered SSH key ID: {connection.ssh_key_id}, path: {device['key_file']}")
        elif connection.ssh_key_name:
            # Look up key ID by name
            key_id = get_ssh_key_id_by_name(connection.ssh_key_name)
            if not key_id:
                logger.error(f"SSH key name not found: {connection.ssh_key_name}")
                raise HTTPException(
                    status_code=400, 
                    detail=f"SSH key with name '{connection.ssh_key_name}' not found"
                )
            device['key_file'] = ssh_keys[key_id]["path"]
            logger.debug(f"Using registered SSH key name: {connection.ssh_key_name}, path: {device['key_file']}")
        elif connection.key_file:
            device['key_file'] = connection.key_file
            logger.debug(f"Using direct key file: {connection.key_file}")
            # Verify key file exists
            if not os.path.exists(connection.key_file):
                logger.error(f"Key file does not exist: {connection.key_file}")
                raise HTTPException(
                    status_code=400,
                    detail=f"SSH key file not found: {connection.key_file}"
                )
        else:
            logger.error("No SSH key specified (id, name, or file)")
            raise HTTPException(
                status_code=400, 
                detail="When using SSH key authentication, you must provide either ssh_key_id, ssh_key_name, or key_file"
            )
            
        if connection.passphrase:
            device['passphrase'] = connection.passphrase
            logger.debug("Using key passphrase")
    else:
        # Use password authentication
        if not connection.password:
            logger.error("Password authentication selected but no password provided")
            raise HTTPException(
                status_code=400, 
                detail="Password is required when not using SSH key authentication"
            )
        device['password'] = connection.password
        logger.debug(f"Using password authentication for {connection.username}@{connection.host}")
    
    try:
        logger.debug(f"Attempting to establish connection to {connection.host}")
        new_connection = netmiko.ConnectHandler(**device)
        logger.debug(f"Connection established successfully to {connection.host}")
        
        # Cache the new connection
        connection_cache[cache_key] = {
            'connection': new_connection,
            'expires': datetime.now() + timedelta(seconds=CONNECTION_CACHE_TTL)
        }
        return new_connection
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Connection failed: {error_msg}")
        # Log more details about the connection attempt (but not the password/key)
        logger.error(f"Connection details: host={connection.host}, port={connection.port}, "
                    f"username={connection.username}, use_keys={connection.use_keys}")
        if connection.use_keys and 'key_file' in device:
            logger.error(f"Key file used: {device['key_file']}")
            # Check if key file exists and has correct permissions
            if os.path.exists(device['key_file']):
                key_perms = oct(os.stat(device['key_file']).st_mode)[-3:]
                logger.error(f"Key file exists, permissions: {key_perms}")
                # Try to read the first line to verify it's a valid key
                try:
                    with open(device['key_file'], 'r') as f:
                        first_line = f.readline().strip()
                        logger.error(f"Key file first line: {first_line[:20]}...")
                except Exception as read_err:
                    logger.error(f"Failed to read key file: {read_err}")
            else:
                logger.error("Key file does not exist")
        
        raise HTTPException(status_code=500, detail=f"Failed to connect to VyOS router: {error_msg}")

class CommandExecutor:
    """Handles command execution in both direct and remote modes"""
    
    @staticmethod
    def execute_command(connection: VyOSConnection, command: str):
        """Execute a command on the VyOS router"""
        logger.debug(f"Executing command: {command}")
        try:
            if DEPLOYMENT_MODE == "direct":
                logger.debug("Using direct execution mode")
                result = execute_local_command(command)
                logger.debug(f"Command executed successfully (direct mode), result length: {len(result)}")
                return result
            else:  # remote mode
                logger.debug("Using remote execution mode")
                device = get_vyos_connection(connection)
                result = device.send_command(command)
                logger.debug(f"Command executed successfully (remote mode), result length: {len(result)}")
                return result
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Command execution failed: {error_msg}")
            raise Exception(f"Command execution failed: {error_msg}")
    
    @staticmethod
    def execute_multiple_commands(connection: VyOSConnection, commands: Dict[str, str]):
        """Execute multiple commands and return results dictionary"""
        results = {}
        
        logger.debug(f"Executing multiple commands: {list(commands.keys())}")
        
        try:
            if DEPLOYMENT_MODE == "direct":
                logger.debug("Using direct execution mode for multiple commands")
                for cmd_name, cmd in commands.items():
                    logger.debug(f"Executing command '{cmd_name}': {cmd}")
                    results[cmd_name] = execute_local_command(cmd)
            else:  # remote mode
                logger.debug("Using remote execution mode for multiple commands")
                device = get_vyos_connection(connection)
                for cmd_name, cmd in commands.items():
                    logger.debug(f"Executing command '{cmd_name}': {cmd}")
                    results[cmd_name] = device.send_command(cmd)
            
            logger.debug("All commands executed successfully")
            return results
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Multiple command execution failed: {error_msg}")
            raise Exception(f"Multiple command execution failed: {error_msg}")
    
    @staticmethod
    def read_file(connection: VyOSConnection, file_path: str):
        """Read a file from the VyOS router"""
        logger.debug(f"Reading file: {file_path}")
        try:
            if DEPLOYMENT_MODE == "direct":
                logger.debug("Using direct file reading")
                with open(file_path, 'r') as f:
                    content = f.read()
                logger.debug(f"File read successfully (direct mode), content length: {len(content)}")
                return content
            else:  # remote mode
                logger.debug("Using remote file reading")
                device = get_vyos_connection(connection)
                content = device.send_command(f"cat {file_path}")
                logger.debug(f"File read successfully (remote mode), content length: {len(content)}")
                return content
        except Exception as e:
            error_msg = str(e)
            logger.error(f"File reading failed: {error_msg}")
            raise Exception(f"Failed to read file {file_path}: {error_msg}")

def get_vyos_connection(connection: VyOSConnection):
    """Get a VyOS connection (cached or new)"""
    if DEPLOYMENT_MODE == "direct":
        # No need for SSH connection in direct mode
        return None
    
    if not connection.host or not connection.username:
        logger.error("Missing required connection parameters (host or username)")
        raise HTTPException(
            status_code=400, 
            detail="Remote mode requires host and username"
        )
    
    if not connection.use_keys and not connection.password:
        logger.error("No authentication method provided (neither password nor SSH key)")
        raise HTTPException(
            status_code=400, 
            detail="Either password or SSH key authentication (use_keys=True) is required"
        )
    
    # Extra debug for key files if they're provided directly
    if connection.use_keys and connection.key_file:
        # Verify the key path exists - could be a temporary path created by frontend
        if not os.path.isabs(connection.key_file):
            # Try to locate the key in temp directory or ssh keys directory
            possible_paths = [
                connection.key_file,
                os.path.join(TEMP_KEY_DIR, connection.key_file),
                os.path.join(SSH_KEYS_DIR, connection.key_file)
            ]
            
            for path in possible_paths:
                if os.path.exists(path):
                    logger.debug(f"Found key file at: {path}")
                    connection.key_file = path
                    break
            else:
                # Could not find the key file anywhere
                logger.error(f"SSH key file not found in any location: {possible_paths}")
                logger.debug(f"Current working directory: {os.getcwd()}")
                logger.debug(f"TEMP_KEY_DIR contents: {os.listdir(TEMP_KEY_DIR) if os.path.exists(TEMP_KEY_DIR) else 'directory does not exist'}")
                logger.debug(f"SSH_KEYS_DIR contents: {os.listdir(SSH_KEYS_DIR) if os.path.exists(SSH_KEYS_DIR) else 'directory does not exist'}")
                raise HTTPException(
                    status_code=400,
                    detail=f"SSH key file not found: {connection.key_file}"
                )
    
    try:
        return get_cached_connection(connection)
    except Exception as e:
        logger.error(f"Failed to get VyOS connection: {str(e)}")
        logger.error(traceback.format_exc())
        raise

def cleanup_connection_cache(background_tasks: BackgroundTasks):
    """Clean up expired connections in the cache"""
    if DEPLOYMENT_MODE == "direct":
        # No connections to clean up in direct mode
        return
    
    def _cleanup():
        now = datetime.now()
        keys_to_remove = []
        
        for key, cached_conn in connection_cache.items():
            if cached_conn['expires'] < now or not cached_conn['connection'].is_alive():
                try:
                    cached_conn['connection'].disconnect()
                except:
                    pass
                keys_to_remove.append(key)
        
        for key in keys_to_remove:
            del connection_cache[key]
    
    background_tasks.add_task(_cleanup)

@app.post("/connect", response_model=VyOSResponse)
async def connect_to_router(connection: VyOSConnection, background_tasks: BackgroundTasks, api_key: APIKey = Depends(get_api_key)):
    try:
        if DEPLOYMENT_MODE == "direct":
            # Just check if we're running on VyOS
            version_info = execute_local_command("cat /etc/version")
            if "vyos" not in version_info.lower():
                raise Exception("Not running on a VyOS system")
            
            return VyOSResponse(
                success=True,
                data={"status": "connected", "mode": "direct", "version": version_info.strip()},
                message="Running directly on VyOS system"
            )
        else:
            # Remote mode - establish SSH connection
            device = get_vyos_connection(connection)
            cleanup_connection_cache(background_tasks)
            return VyOSResponse(
                success=True,
                data={"status": "connected", "mode": "remote"},
                message="Successfully connected to VyOS router"
            )
    except Exception as e:
        return VyOSResponse(
            success=False,
            data={"error": str(e)},
            message="Failed to connect to VyOS router"
        )

def parse_vyos_config_to_dict(config_text):
    """Convert VyOS text configuration to a properly nested dictionary"""
    lines = config_text.strip().split('\n')
    result = {}
    
    # Stack to track the current path in the configuration hierarchy
    path_stack = []
    # Dictionary to track the current node at each level
    node_stack = [result]
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
        
        # Calculate the indentation level (count of spaces at the beginning divided by 4)
        indent = len(line) - len(line.lstrip())
        level = indent // 4
        
        # Adjust the stack to match the current level
        while len(path_stack) > level:
            path_stack.pop()
            node_stack.pop()
        
        line = line.strip()
        
        if line.endswith(' {'):
            # This is a section opening
            section_name = line[:-2].strip()
            
            # Check if this is a "special" section with an identifier
            if " " in section_name:
                parts = section_name.split(' ', 1)
                section_type = parts[0].strip()
                section_id = parts[1].strip()
                
                # Create or get the section type container
                if section_type not in node_stack[-1]:
                    node_stack[-1][section_type] = {}
                
                # Add the specific instance
                if section_id not in node_stack[-1][section_type]:
                    node_stack[-1][section_type][section_id] = {}
                
                # Update stacks
                path_stack.append((section_type, section_id))
                node_stack.append(node_stack[-1][section_type][section_id])
            else:
                # Regular section
                if section_name not in node_stack[-1]:
                    node_stack[-1][section_name] = {}
                
                # Update stacks
                path_stack.append((section_name,))
                node_stack.append(node_stack[-1][section_name])
        
        elif line == '}':
            # Just a closing bracket, no action needed
            # The stack adjustment at the beginning of the loop will handle it
            continue
        
        else:
            # This is a key-value line
            if " " in line:
                key, value = line.split(' ', 1)
                key = key.strip()
                value = value.strip()
                
                # Handle lists (like name-server may have multiple values)
                if key in node_stack[-1] and isinstance(node_stack[-1][key], list):
                    node_stack[-1][key].append(value)
                elif key in node_stack[-1] and not isinstance(node_stack[-1][key], dict):
                    # Convert to list if we encounter a second value
                    node_stack[-1][key] = [node_stack[-1][key], value]
                else:
                    node_stack[-1][key] = value
            else:
                # Just a flag without a value
                node_stack[-1][line] = {}
    
    return result

@app.post("/get-config", response_model=VyOSResponse)
async def get_router_config(connection: VyOSConnection, background_tasks: BackgroundTasks, format_type: str = "json", api_key: APIKey = Depends(get_api_key)):
    try:
        # Log the complete request data (excluding sensitive info)
        log_data = {
            "host": connection.host,
            "username": connection.username,
            "port": connection.port,
            "use_keys": connection.use_keys,
            "format": format_type
        }
        
        if connection.use_keys:
            log_data["key_method"] = "key_file" if connection.key_file else "ssh_key_id" if connection.ssh_key_id else "ssh_key_name"
            if connection.key_file:
                log_data["key_file"] = connection.key_file
        
        logger.info(f"Get configuration request: {json.dumps(log_data)}")
        
        # Create a command executor that works in both modes
        executor = CommandExecutor()
        
        if format_type.lower() == "json":
            # Use the direct JSON format command
            try:
                logger.debug("Executing 'show configuration json' command")
                config = executor.execute_command(connection, "show configuration json")
                logger.debug(f"JSON configuration retrieved, length: {len(config)}")
                
                try:
                    # Try to parse as JSON
                    logger.debug("Parsing JSON configuration")
                    config_json = json.loads(config)
                    cleanup_connection_cache(background_tasks)
                    logger.info("Successfully retrieved and parsed VyOS configuration in JSON format")
                    return VyOSResponse(
                        success=True,
                        data={"config": config_json},
                        message="Successfully retrieved VyOS configuration in JSON format"
                    )
                except json.JSONDecodeError as e:
                    # Fallback to text format if JSON parsing fails
                    logger.warning(f"Failed to parse JSON configuration: {str(e)}")
                    logger.debug(f"Raw config sample: {config[:500]}")
                    logger.debug("Falling back to text format")
                    
                    config = executor.execute_command(connection, "show configuration")
                    cleanup_connection_cache(background_tasks)
                    logger.info("Retrieved VyOS configuration in text format (JSON parse failed)")
                    return VyOSResponse(
                        success=False,
                        data={"error": str(e), "raw_config": config},
                        message="Failed to parse VyOS configuration as JSON"
                    )
            except Exception as cmd_error:
                logger.error(f"Command execution error: {str(cmd_error)}")
                raise Exception(f"Failed to execute configuration command: {str(cmd_error)}")
        else:
            # Return plain text format
            logger.debug("Requesting text format configuration")
            config = executor.execute_command(connection, "show configuration")
            cleanup_connection_cache(background_tasks)
            logger.info("Successfully retrieved VyOS configuration in text format")
            return VyOSResponse(
                success=True,
                data={"config": config},
                message="Successfully retrieved VyOS configuration in text format"
            )
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Failed to retrieve VyOS configuration: {error_msg}")
        
        # Enhanced error reporting
        logger.error(traceback.format_exc())
        
        # Debug info about the connection
        conn_info = {
            "host": connection.host,
            "username": connection.username,
            "port": connection.port,
            "use_keys": connection.use_keys
        }
        
        if connection.use_keys:
            if connection.key_file:
                conn_info["key_file"] = connection.key_file
                # Check if key file exists and has correct permissions
                if os.path.exists(connection.key_file):
                    key_perms = oct(os.stat(connection.key_file).st_mode)[-3:]
                    conn_info["key_file_exists"] = True
                    conn_info["key_file_permissions"] = key_perms
                    
                    # Try to read first few characters to check if it's valid
                    try:
                        with open(connection.key_file, 'r') as f:
                            first_line = f.readline().strip()
                            conn_info["key_file_starts_with"] = first_line[:20] + "..."
                    except Exception as read_err:
                        conn_info["key_file_read_error"] = str(read_err)
                else:
                    conn_info["key_file_exists"] = False
                    # List directory contents to help debug
                    if os.path.dirname(connection.key_file):
                        dir_path = os.path.dirname(connection.key_file)
                        if os.path.exists(dir_path):
                            conn_info["directory_contents"] = os.listdir(dir_path)
                        else:
                            conn_info["directory_exists"] = False
            elif connection.ssh_key_id:
                conn_info["ssh_key_id"] = connection.ssh_key_id
                conn_info["ssh_key_exists"] = connection.ssh_key_id in ssh_keys
            elif connection.ssh_key_name:
                conn_info["ssh_key_name"] = connection.ssh_key_name
                key_id = get_ssh_key_id_by_name(connection.ssh_key_name)
                conn_info["ssh_key_id_found"] = key_id is not None
        
        logger.error(f"Connection debug info: {json.dumps(conn_info, default=str)}")
        
        # If error message is empty, provide a more helpful one
        if not error_msg:
            error_msg = "Unknown error occurred, check server logs for details"
            logger.error("Empty error message received, setting generic error")
        
        return VyOSResponse(
            success=False,
            data={"error": error_msg},
            message="Failed to retrieve VyOS configuration"
        )

@app.post("/get-interfaces", response_model=VyOSResponse)
async def get_interfaces(connection: VyOSConnection, background_tasks: BackgroundTasks, api_key: APIKey = Depends(get_api_key)):
    try:
        executor = CommandExecutor()
        
        # Get the configuration in JSON format
        config = executor.execute_command(connection, "show configuration json")
        try:
            config_json = json.loads(config)
            
            # Extract just the interfaces section
            interfaces_data = config_json.get("interfaces", {})
            
            cleanup_connection_cache(background_tasks)
            return VyOSResponse(
                success=True,
                data={"interfaces": interfaces_data},
                message="Successfully retrieved interface information"
            )
        except json.JSONDecodeError:
            # Fallback to using show interfaces
            interfaces = executor.execute_command(connection, "show interfaces")
            cleanup_connection_cache(background_tasks)
            return VyOSResponse(
                success=True,
                data={"interfaces": interfaces},
                message="Successfully retrieved interface information in text format"
            )
    except Exception as e:
        return VyOSResponse(
            success=False,
            data={"error": str(e)},
            message="Failed to retrieve interface information"
        )

def parse_dhcp_leases(leases_text):
    """Parse DHCP leases file into structured data"""
    leases = []
    current_lease = None
    
    for line in leases_text.splitlines():
        line = line.strip()
        
        # Skip comments and empty lines
        if not line or line.startswith('#') or line.startswith('authoring-byte-order') or line.startswith('server-duid'):
            continue
            
        # New lease entry
        if line.startswith('lease '):
            if current_lease:
                leases.append(current_lease)
            
            # Extract IP address
            ip_address = line.split()[1]
            current_lease = {"ip_address": ip_address, "properties": {}}
            
        # End of lease entry
        elif line == '}':
            if current_lease:
                leases.append(current_lease)
                current_lease = None
                
        # Lease properties
        elif current_lease and ';' in line:
            # Split the line into key-value parts
            parts = line.split(';')[0].strip().split(' ', 1)
            if len(parts) >= 2:
                key = parts[0]
                value = parts[1].strip().strip('"')
                
                # Handle specific fields
                if key == 'hardware':
                    # Parse hardware ethernet xx:xx:xx:xx:xx:xx
                    hw_parts = value.split()
                    if len(hw_parts) == 2:
                        current_lease["mac_address"] = hw_parts[1]
                elif key == 'client-hostname':
                    current_lease["hostname"] = value
                elif key in ['starts', 'ends', 'cltt']:
                    # Format: starts 1 2025/03/17 12:38:18
                    date_parts = value.split(' ', 1)
                    if len(date_parts) >= 2:
                        current_lease[key] = date_parts[1]
                elif key == 'binding':
                    # Handle binding state active
                    state_parts = value.split()
                    if len(state_parts) >= 2 and state_parts[0] == 'state':
                        current_lease["binding_state"] = state_parts[1]
                else:
                    current_lease["properties"][key] = value
    
    # Add the last lease if exists
    if current_lease:
        leases.append(current_lease)
        
    return leases

@app.post("/get-dhcp-config", response_model=VyOSResponse)
async def get_dhcp_config(connection: VyOSConnection, background_tasks: BackgroundTasks, api_key: APIKey = Depends(get_api_key)):
    try:
        executor = CommandExecutor()
        
        # Commands to execute
        commands = {
            "config": "show configuration json",
            "leases_summary": "show dhcp server leases"
        }
        
        # Get DHCP leases file
        if DEPLOYMENT_MODE == "direct":
            # Read file directly
            leases_file = executor.read_file(connection, VYOS_DHCP_LEASES_FILE)
        else:
            # Use SSH cat command
            commands["leases_file"] = f"cat {VYOS_DHCP_LEASES_FILE}"
        
        # Execute commands
        results = executor.execute_multiple_commands(connection, commands)
        
        # If in direct mode, add the leases file content to results
        if DEPLOYMENT_MODE == "direct":
            results["leases_file"] = leases_file
        
        try:
            config_json = json.loads(results["config"])
            
            # Extract DHCP server configuration if it exists
            dhcp_data = {}
            if "service" in config_json and "dhcp-server" in config_json["service"]:
                dhcp_data = config_json["service"]["dhcp-server"]
            
            # Parse the leases file into structured data
            parsed_leases = parse_dhcp_leases(results["leases_file"])
            
            cleanup_connection_cache(background_tasks)
            return VyOSResponse(
                success=True,
                data={
                    "dhcp_config": dhcp_data,
                    "dhcp_leases": {
                        "structured": parsed_leases,
                        "summary": results["leases_summary"],
                        "raw_file": results["leases_file"]
                    }
                },
                message="Successfully retrieved DHCP server information with leases"
            )
        except json.JSONDecodeError as e:
            cleanup_connection_cache(background_tasks)
            return VyOSResponse(
                success=False,
                data={"error": str(e)},
                message="Failed to parse VyOS configuration JSON"
            )
    except Exception as e:
        return VyOSResponse(
            success=False,
            data={"error": str(e)},
            message="Failed to retrieve DHCP server information"
        )

@app.post("/get-system-info", response_model=VyOSResponse)
async def get_system_info(connection: VyOSConnection, background_tasks: BackgroundTasks, api_key: APIKey = Depends(get_api_key)):
    try:
        executor = CommandExecutor()
        system_info = executor.execute_command(connection, "show system information")
        cleanup_connection_cache(background_tasks)
        return VyOSResponse(
            success=True,
            data={"system_info": system_info},
            message="Successfully retrieved system information"
        )
    except Exception as e:
        return VyOSResponse(
            success=False,
            data={"error": str(e)},
            message="Failed to retrieve system information"
        )

@app.post("/upload-ssh-key", response_model=VyOSResponse)
async def upload_ssh_key(key_data: SSHKeyUpload, background_tasks: BackgroundTasks, api_key: APIKey = Depends(get_api_key)):
    """Upload an SSH private key and store it temporarily for connection"""
    try:
        # Generate a unique ID for this key
        key_id = str(uuid.uuid4())
        key_name = key_data.key_name or f"temp_key_{key_id}.pem"
        key_path = os.path.join(TEMP_KEY_DIR, key_name)
        
        logger.debug(f"Writing SSH key to: {key_path}")
        
        # Write the key content to a file with proper permissions
        with open(key_path, 'w') as f:
            key_content = key_data.key_content.strip()
            # Quick validation - check if it looks like a private key
            if not (key_content.startswith('-----BEGIN') and 'PRIVATE KEY' in key_content.splitlines()[0]):
                logger.warning(f"Key doesn't appear to be in valid format, first line: {key_content.splitlines()[0][:40]}...")
            
            f.write(key_content)
            logger.debug(f"Key file written, size: {len(key_content)} bytes")
        
        # Set correct permissions for SSH key (required for SSH to work)
        os.chmod(key_path, 0o600)
        logger.debug(f"Key file permissions set to 0o600")
        
        # Verify the key was written correctly
        if os.path.exists(key_path):
            file_size = os.path.getsize(key_path)
            logger.debug(f"Key file exists, size: {file_size} bytes")
            
            # Check if the file is readable
            try:
                with open(key_path, 'r') as f:
                    first_line = f.readline().strip()
                    logger.debug(f"Key file is readable, first line: {first_line[:40]}...")
            except Exception as e:
                logger.error(f"Could not read back key file: {str(e)}")
        else:
            logger.error(f"Key file was not created at: {key_path}")
        
        # Store key info with expiry time
        expiry_time = datetime.now() + timedelta(seconds=KEY_EXPIRY_SECONDS)
        temp_keys[key_id] = {
            "path": key_path,
            "expires": expiry_time
        }
        
        logger.debug(f"Temporary key stored with ID: {key_id}, expires: {expiry_time}")
        
        # Schedule key deletion after expiry
        background_tasks.add_task(delete_expired_key, key_id)
        
        return VyOSResponse(
            success=True,
            data={"key_id": key_id, "key_path": key_path},
            message="SSH key uploaded successfully"
        )
    except Exception as e:
        logger.error(f"Failed to upload SSH key: {str(e)}")
        logger.error(traceback.format_exc())
        return VyOSResponse(
            success=False,
            data={"error": str(e)},
            message="Failed to upload SSH key"
        )

def delete_expired_key(key_id):
    """Delete an SSH key after it expires"""
    # Sleep until key expires
    if key_id in temp_keys:
        seconds_to_expiry = (temp_keys[key_id]["expires"] - datetime.now()).total_seconds()
        if seconds_to_expiry > 0:
            time.sleep(seconds_to_expiry)
        
        # Delete the key if it still exists
        if key_id in temp_keys:
            try:
                os.remove(temp_keys[key_id]["path"])
            except Exception:
                pass
            del temp_keys[key_id]

@app.post("/cleanup-keys", response_model=VyOSResponse)
async def cleanup_all_keys(api_key: APIKey = Depends(get_api_key)):
    """Cleanup all temporary SSH keys"""
    deleted_count = 0
    
    for key_id, key_info in list(temp_keys.items()):
        try:
            os.remove(key_info["path"])
            del temp_keys[key_id]
            deleted_count += 1
        except Exception:
            pass
    
    return VyOSResponse(
        success=True,
        data={"deleted_count": deleted_count},
        message=f"Cleaned up {deleted_count} temporary SSH keys"
    )

@app.post("/ssh-keys/register", response_model=Dict[str, str])
async def register_ssh_key(new_key: NewSSHKey, api_key: APIKey = Depends(get_api_key)):
    """Register a new SSH key with the given name"""
    try:
        # Generate a unique ID for this key
        key_id = str(uuid.uuid4())
        key_path = os.path.join(SSH_KEYS_DIR, f"key_{key_id}.pem")
        
        # Write the key content to a file with proper permissions
        with open(key_path, 'w') as f:
            f.write(new_key.key_content)
        
        # Set correct permissions for SSH key (required for SSH to work)
        os.chmod(key_path, 0o600)
        
        # Store key info
        ssh_keys[key_id] = {
            "name": new_key.name,
            "path": key_path,
            "created_at": datetime.now()
        }
        
        print(f"Registered new SSH key with name: {new_key.name}")
        print("Reminder: SSH keys are stored on disk but the mapping is in memory.")
        print("Keys will need to be re-registered after server restart.")
        
        return {"id": key_id, "name": new_key.name}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to register SSH key: {str(e)}")

@app.get("/ssh-keys/list", response_model=List[RegisteredSSHKey])
async def list_ssh_keys(api_key: APIKey = Depends(get_api_key)):
    """List all registered SSH keys"""
    return [
        RegisteredSSHKey(id=key_id, name=info["name"], created_at=info["created_at"])
        for key_id, info in ssh_keys.items()
    ]

@app.delete("/ssh-keys/{key_id}", response_model=Dict[str, str])
async def delete_ssh_key(key_id: str, api_key: APIKey = Depends(get_api_key)):
    """Delete a registered SSH key by ID"""
    if key_id not in ssh_keys:
        raise HTTPException(status_code=404, detail=f"SSH key with ID {key_id} not found")
    
    # Remove the key file
    try:
        os.remove(ssh_keys[key_id]["path"])
    except Exception as e:
        print(f"Warning: Could not delete SSH key file: {str(e)}")
    
    # Remove from registry
    key_name = ssh_keys[key_id]["name"]
    del ssh_keys[key_id]
    
    return {"message": f"SSH key '{key_name}' deleted successfully"}

# Add a method to get SSH key ID by name
def get_ssh_key_id_by_name(key_name: str):
    """Get the ID of an SSH key by name"""
    for key_id, info in ssh_keys.items():
        if info["name"] == key_name:
            return key_id
    return None

# Add cleanup routine when server starts
@app.on_event("startup")
async def startup_event():
    """Clean any leftover temporary keys when server starts"""
    if os.path.exists(TEMP_KEY_DIR):
        for key_file in os.listdir(TEMP_KEY_DIR):
            try:
                os.remove(os.path.join(TEMP_KEY_DIR, key_file))
            except Exception:
                pass
    
    # Check for existing SSH keys in the SSH_KEYS_DIR
    print("Looking for existing SSH keys...")
    if os.path.exists(SSH_KEYS_DIR):
        for key_file in os.listdir(SSH_KEYS_DIR):
            if key_file.startswith("key_") and key_file.endswith(".pem"):
                try:
                    # Extract key ID from filename
                    key_id = key_file[4:-4]  # Remove "key_" prefix and ".pem" suffix
                    key_path = os.path.join(SSH_KEYS_DIR, key_file)
                    
                    # Add to registry with default name based on file
                    ssh_keys[key_id] = {
                        "name": f"key_{key_id[:8]}",  # Use shortened ID as name
                        "path": key_path,
                        "created_at": datetime.fromtimestamp(os.path.getctime(key_path))
                    }
                    print(f"Loaded existing SSH key: {key_id}")
                except Exception as e:
                    print(f"Failed to load SSH key {key_file}: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=HOST, port=PORT) 