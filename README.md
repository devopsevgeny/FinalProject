# Configuration manager API documentation

FastAPI-based service for managing configurations and secrets with versioning, encryption, and audit logging.

## Authentication

Set `AUTH_TYPE` to choose an authentication mode.

### API key authentication — `AUTH_TYPE=API_KEY`

```bash
curl -H "X-API-Key: your-api-key" http://localhost:8080/whoami
```

### JSON Web Token bearer authentication — `AUTH_TYPE=BEARER`

```bash
curl -H "Authorization: Bearer your.jwt.token" http://localhost:8080/whoami
```

## Health check endpoints

### Endpoint: GET /health

Checks service and database health.

```bash
curl http://localhost:8080/health
```

### Endpoint: GET /healthz

Exposes a Kubernetes-style health probe.

```bash
curl http://localhost:8080/healthz
```

## Authentication information

### Endpoint: GET /whoami

Returns authenticated principal details.

```bash
# With API key
curl -H "X-API-Key: your-api-key" http://localhost:8080/whoami

# With JSON Web Token
curl -H "Authorization: Bearer your.jwt.token" http://localhost:8080/whoami
```

Example response:

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

## Configuration endpoints

### Endpoint: GET /config/{path}

Retrieves the current configuration value (JSON or file metadata).

```bash
curl -H "X-API-Key: your-api-key" \
  "http://localhost:8080/config/myapp/settings?appId=myapp"
```

```json
{
  "path": "myapp/settings",
  "version": 1,
  "data_type": "json",
  "value": {"feature": true},
  "file_name": null,
  "file_size": null,
  "created_at": "2025-09-25T12:00:00Z"
}
```

### Endpoint: POST /config/{path}

Creates or updates a JSON configuration document.

```bash
curl -X POST \
     -H "X-API-Key: your-api-key" \
     -H "Content-Type: application/json" \
     -H "X-Actor-Id: user123" \
     -d '{"app_id": "myapp", "app_name": "My App", "value": {"feature": true}}' \
     "http://localhost:8080/config/myapp/settings"
```

### Endpoint: POST /config/{path}/file

Uploads a configuration file (binary payload stored as a versioned blob).

```bash
curl -X POST \
     -H "X-API-Key: your-api-key" \
     -H "X-Actor-Id: user123" \
     -F app_id=myapp \
     -F app_name="My App" \
     -F file=@config.yaml \
     http://localhost:8080/config/myapp/settings/file
```

### Endpoint: GET /config/{path}/file

Downloads the current or specific file-backed configuration.

```bash
# Current version
curl -OJ -H "X-API-Key: your-api-key" \
  "http://localhost:8080/config/myapp/settings/file?appId=myapp"

# Specific version
curl -OJ -H "X-API-Key: your-api-key" \
  "http://localhost:8080/config/myapp/settings/file?appId=myapp&version=3"
```

## Secret endpoints

### Endpoint: GET /secret/{path}

Retrieves the decrypted secret value.

```bash
# Current version
curl -H "X-API-Key: your-api-key" http://localhost:8080/secret/myapp/api-key

# Specific version
curl -H "X-API-Key: your-api-key" http://localhost:8080/secret/myapp/api-key?version=2
```

```json
{
  "path": "myapp/api-key",
  "version": 1,
  "value": {"key": "secret-value"},
  "created_at": "2025-09-25T12:00:00Z"
}
```

### Endpoint: POST /secret/{path}

Creates or updates an encrypted secret.

```bash
curl -X POST \
     -H "X-API-Key: your-api-key" \
     -H "Content-Type: application/json" \
     -H "X-Actor-Id: user123" \
     -d '{"app_id": "myapp", "app_name": "My App", "value": {"key": "secret-value"}}' \
     http://localhost:8080/secret/myapp/api-key
```

## Path format

Paths must follow these rules:

- Contain letters, numbers, dots, underscores, or hyphens
- Use forward slashes between segments
- No trailing slash
- Examples: `myapp/settings`, `service/api-key`, `auth.credentials`

## Audit trail

All write operations are logged with:

- Actor ID (from the `X-Actor-Id` header or authentication principal)
- Actor subject (from the `X-Actor-Subject` header or JSON Web Token)
- Operation type
- Target path
- Version metadata

## Environment variables

```bash
# Authentication
export AUTH_TYPE=API_KEY           # or BEARER
export API_KEY=your-secret-key     # used for API key mode
export JWT_SIGNING_KEY=secret      # signing key for JSON Web Token mode
export JWT_AUDIENCE=confmgr
export ISSUER=your-issuer

# Cross-origin resource sharing
export CORS_ORIGINS=http://localhost:3000,https://app.example.com

# Config file uploads
export CONFIG_FILE_MAX_BYTES=5242880            # 5 MiB default
export CONFIG_FILE_ALLOWED_PREFIXES=application/,text/,image/svg+xml
```

## Security features

1. Path validation to block traversal attacks
2. AES-GCM encryption for secrets
3. Version binding for encrypted data
4. SHA-256 integrity checks for configuration payloads
5. File uploads constrained by size and media-type allow-list
6. Optimistic locking for atomic updates
7. Comprehensive audit logging
8. Cross-origin resource sharing (CORS) protection with explicit origins

## Error responses

```json
{
  "detail": "error message"
}
```

Common status codes:

- 400 — invalid input or path format
- 401 — authentication failed
- 404 — configuration or secret not found
- 500 — internal server error
