# VyOS Router Manager API

A FastAPI application that provides an API interface to interact with VyOS routers in both direct and remote modes.

## Features

- Connect to VyOS routers
- Retrieve router configuration in JSON format
- Get interface information
- Get DHCP server configuration and lease information
- Get system information
- API key authentication
- Support for running directly on a VyOS router or from a remote machine

## Installation

1. Clone this repository
2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Configuration

All configuration is done through environment variables in a `.env` file. A sample `.env.example` file is provided.

1. Copy the example file to create your own configuration:
```bash
cp .env.example .env
```

2. Edit the `.env` file to configure:
   - Deployment mode (`direct` or `remote`)
   - API keys
   - Server settings
   - VyOS configuration paths

### API Keys

API keys are defined in the `.env` file in the format:
```
API_KEYS=name1:key1,name2:key2
```

For example:
```
API_KEYS=admin:YOUR_ADMIN_KEY,readonly:YOUR_READONLY_KEY
```

If no API keys are provided, a default key will be generated when you first run the application and displayed in the console. You should add this key to your `.env` file if you want it to persist between restarts.

**Important Note**: API keys are stored in memory only. If you generate or delete keys using the API during runtime, these changes will be lost when the server restarts. To make API key changes permanent, always update your `.env` file.

## Usage

### Starting the API Server

Run the FastAPI application:
```bash
python main.py
```

### Direct Mode

When running in `direct` mode (on a VyOS router), no connection information is needed in API requests.

Example:
```bash
curl -X POST "http://localhost:8000/get-config" \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{}'
```

### Remote Mode

When running in `remote` mode (connecting to a VyOS router), you need to provide connection details.

#### Password Authentication

Example:
```bash
curl -X POST "http://localhost:8000/get-config" \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"host": "your-vyos-router-ip", "username": "your-username", "password": "your-password"}'
```

#### SSH Key Authentication

Example:
```bash
curl -X POST "http://localhost:8000/get-config" \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"host": "your-vyos-router-ip", "username": "your-username", "use_keys": true, "key_file": "/path/to/private_key"}'
```

If your private key is password protected, you can also include the passphrase:
```bash
curl -X POST "http://localhost:8000/get-config" \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"host": "your-vyos-router-ip", "username": "your-username", "use_keys": true, "key_file": "/path/to/private_key", "passphrase": "your-key-passphrase"}'
```

## API Endpoints

The following endpoints are available:
See more details in /docs
### Connection
- **POST** `/connect` - Test connection to the VyOS router

### Configuration
- **POST** `/get-config` - Get router configuration (JSON or text format)
- **POST** `/get-interfaces` - Get interface information
- **POST** `/get-dhcp-config` - Get DHCP server configuration and leases
- **POST** `/get-system-info` - Get system information

### API Key Management
- **POST** `/api-keys/generate` - Generate a new API key (temporary, until restart)
- **GET** `/api-keys/list` - List all API keys
- **DELETE** `/api-keys/{key_name}` - Delete an API key (temporary, until restart)

## Security Considerations

- Always define your API keys in the `.env` file to ensure they persist between server restarts
- Consider using HTTPS in production
- Store sensitive information (passwords) securely
- For production use, consider implementing a database-backed authentication system
