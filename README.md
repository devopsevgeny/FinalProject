# Configuration manager API documentation

The configuration manager is a FastAPI service that stores versioned configuration data and encrypted secrets. It exposes a concise HTTP surface so platform teams can automate deployments while keeping change history and audit trails.

## Authentication options

Set the `AUTH_TYPE` environment variable to decide how clients authenticate.

### API key mode

Set `AUTH_TYPE=API_KEY`. Every request must send `X-API-Key: <your key>`.

```bash
curl -H "X-API-Key: your-api-key" http://localhost:8080/whoami
```

### Bearer mode with JSON web tokens

Set `AUTH_TYPE=BEARER`. Provide `Authorization: Bearer <jwt>` where the JSON web token—commonly shortened to JWT—is signed with your shared key or key pair.

```bash
curl -H "Authorization: Bearer your.jwt.token" http://localhost:8080/whoami
```

## Health verification endpoints

Automation can poll these endpoints to confirm availability.

- **GET /health**: returns service status and a database round-trip timestamp.
- **GET /healthz**: exposes a Kubernetes-ready probe.

## Identity endpoint

Use **GET /whoami** to see how the service interpreted your credentials.

```bash
curl -H "X-API-Key: your-api-key" http://localhost:8080/whoami
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

Configuration items can hold JSON documents or binary files. Every change creates a new version.

- **GET /config/{path}**: returns the current value. JSON payloads appear in the `value` field. File items include filename, size, and media-type metadata.
- **POST /config/{path}**: accepts a JSON body with `app_id`, optional `app_name`, and `value`.
- **POST /config/{path}/file**: accepts multipart form data with `file`, `app_id` (or `appId`), and optional `app_name` (`appName`).
- **GET /config/{path}/file**: streams the current file, or a specific version when you supply the `version` query parameter.

JSON example:

```bash
curl -X POST \
     -H "X-API-Key: your-api-key" \
     -H "Content-Type: application/json" \
     -d '{"app_id": "myapp", "value": {"feature": true}}' \
     http://localhost:8080/config/myapp/settings
```

File upload example:

```bash
curl -X POST \
     -H "X-API-Key: your-api-key" \
     -F app_id=myapp \
     -F file=@config.yaml \
     http://localhost:8080/config/myapp/settings/file
```

## Secret endpoints

Secrets are stored as JSON values that the service encrypts before persistence.

- **GET /secret/{path}**: returns the decrypted payload for the current version, or a specific version with `?version=<n>`.
- **POST /secret/{path}**: accepts a JSON body with `app_id`, optional `app_name`, and `value` holding a key/value map.

```bash
curl -X POST \
     -H "X-API-Key: your-api-key" \
     -H "Content-Type: application/json" \
     -d '{"app_id": "myapp", "value": {"token": "secret"}}' \
     http://localhost:8080/secret/myapp/api-key
```

## Path rules

Paths must:

- Contain letters, numbers, dots, underscores, or hyphens
- Use forward slashes between segments
- Avoid trailing slashes

Examples: `myapp/settings`, `service/api-key`, `auth.credentials`.

## Audit logging

All write operations record:

- Actor ID from the `X-Actor-Id` header or the authenticated principal
- Actor subject from the `X-Actor-Subject` header or token claims
- Operation type (`config.put`, `secret.put`, and so on)
- Target path and resulting version metadata

## Environment variables

```bash
# Authentication
export AUTH_TYPE=API_KEY            # or BEARER
export API_KEY=your-secret-key      # used for API key mode
export JWT_SIGNING_KEY=secret       # signing key for JWT mode
export JWT_AUDIENCE=confmgr
export ISSUER=your-issuer

# Cross-origin resource sharing
export CORS_ORIGINS=http://localhost:3000,https://app.example.com

# Configuration file uploads
export CONFIG_FILE_MAX_BYTES=5242880             # 5 MiB default
export CONFIG_FILE_ALLOWED_PREFIXES=application/,text/,image/svg+xml
```

## Security features

1. Path validation prevents traversal attacks.
2. Advanced Encryption Standard in Galois/Counter Mode protects secrets; the mode is known as AES-GCM.
3. Version binding keeps encrypted payloads aligned with their metadata.
4. Secure Hash Algorithm 2 confirms payload integrity; the service stores SHA-256 digests.
5. File uploads obey a size and media-type allow-list.
6. Optimistic locking keeps updates atomic.
7. Comprehensive audit logging captures every change.
8. Cross-origin resource sharing protection enforces explicit origins.

## Error responses

```json
{
  "detail": "error message"
}
```

Common status codes:

- 400: invalid input or path format
- 401: authentication failed
- 404: configuration or secret not found
- 500: internal server error

## Running backend tests

Install the backend development requirements before running `pytest` so optional
dependencies—such as `httpx`, which FastAPI's `TestClient` imports at runtime—are
available:

```bash
pip install -r backend/requirements-dev.txt
pytest backend/tests
```

If `httpx` is absent the endpoint test module is skipped with a reminder about
the preceding command.
