# Configuration Manager API Documentation

A FastAPI-based service for managing configurations and secrets with versioning and encryption support.

## Authentication

The service supports two authentication methods, configurable via `AUTH_TYPE` environment variable:

### API Key Authentication (`AUTH_TYPE=API_KEY`)
```bash
curl -H "X-API-Key: your-api-key" http://localhost:8080/whoami
```

### JWT Bearer Authentication (`AUTH_TYPE=BEARER`)
```bash
curl -H "Authorization: Bearer your.jwt.token" http://localhost:8080/whoami
```

## Health Check Endpoints

### GET /health
Check service and database health.
```bash
curl http://localhost:8080/health
```

### GET /healthz
Kubernetes-style health probe.
```bash
curl http://localhost:8080/healthz
```

## Authentication Information

### GET /whoami
Get current authentication details.
```bash
# With API Key
curl -H "X-API-Key: your-api-key" http://localhost:8080/whoami

# With JWT
curl -H "Authorization: Bearer your.jwt.token" http://localhost:8080/whoami
```

Response:
```json
{
    "auth_type": "API_KEY",
    "principal": {
        "id": "api-key",
        "subject": null,
        "issuer": null,
        "scopes": null
    }
}
```

## Configuration Endpoints

### GET /config/{path}
Retrieve configuration value.
```bash
curl -H "X-API-Key: your-api-key" http://localhost:8080/config/myapp/settings
```

Response:
```json
{
    "path": "myapp/settings",
    "version": 1,
    "value": {"setting1": "value1"},
    "created_at": "2025-09-25T12:00:00Z"
}
```

### POST /config/{path}
Create or update configuration.
```bash
curl -X POST \
     -H "X-API-Key: your-api-key" \
     -H "Content-Type: application/json" \
     -d '{"value": {"setting1": "value1"}}' \
     http://localhost:8080/config/myapp/settings
```

## Secret Endpoints

### GET /secret/{path}
Retrieve decrypted secret value.
```bash
# Get current version
curl -H "X-API-Key: your-api-key" http://localhost:8080/secret/myapp/api-key

# Get specific version
curl -H "X-API-Key: your-api-key" http://localhost:8080/secret/myapp/api-key?version=2
```

Response:
```json
{
    "path": "myapp/api-key",
    "version": 1,
    "value": {"key": "secret-value"},
    "created_at": "2025-09-25T12:00:00Z"
}
```

### POST /secret/{path}
Create or update encrypted secret.
```bash
curl -X POST \
     -H "X-API-Key: your-api-key" \
     -H "Content-Type: application/json" \
     -H "X-Actor-Id: user123" \
     -d '{"value": {"key": "secret-value"}}' \
     http://localhost:8080/secret/myapp/api-key
```

## Path Format

Paths must follow these rules:
- Can contain letters, numbers, dots, underscores, and hyphens
- Segments are separated by forward slashes
- No trailing slash
- Examples: `myapp/settings`, `service/api-key`, `auth.credentials`

## Audit Trail

All write operations (PUT config/secret) are logged with:
- Actor ID (from X-Actor-Id header or auth principal)
- Actor subject (from X-Actor-Subject header or JWT)
- Operation type
- Path
- Version information

## Environment Variables

```bash
# Authentication
export AUTH_TYPE=API_KEY           # or BEARER
export API_KEY=your-secret-key     # for API_KEY auth
export JWT_SIGNING_KEY=secret      # for BEARER auth
export JWT_AUDIENCE=confmgr
export ISSUER=your-issuer

# CORS
export CORS_ORIGINS=http://localhost:3000,https://app.example.com
```

## Security Features

1. Path validation to prevent traversal attacks
2. AES-GCM encryption for secrets
3. Version binding for encrypted data
4. Atomic updates with optimistic locking
5. Audit logging for all changes
6. CORS protection with explicit origins

## Error Responses

```json
{
    "detail": "error message"
}
```

Common status codes:
- 400: Invalid path format
- 401: Authentication failed
- 404: Config/secret not found
- 500: Internal server error