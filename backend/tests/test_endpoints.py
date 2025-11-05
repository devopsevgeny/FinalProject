# python
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip(
    "httpx",
    reason=(
        "fastapi.testclient depends on httpx; install backend dev deps with "
        "`pip install -r backend/requirements-dev.txt`"
    ),
)

from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.auth_mode import AUTH_DEP
from app.main import app
from app.security.auth import AuthPrincipal, SYSTEM_PRINCIPAL_ID, resolve_created_by


@pytest.fixture(autouse=True)
def override_auth_dependency():
    """Bypass authentication for unit tests."""
    app.dependency_overrides[AUTH_DEP] = lambda: None
    yield
    app.dependency_overrides.pop(AUTH_DEP, None)


@pytest.fixture
def client():
    return TestClient(app)


def test_resolve_created_by_rejects_invalid_header():
    with pytest.raises(HTTPException) as exc:
        resolve_created_by(None, "not-a-uuid")
    assert exc.value.status_code == 400


def test_resolve_created_by_falls_back_to_system_uuid():
    assert resolve_created_by(None, None) == SYSTEM_PRINCIPAL_ID


def test_resolve_created_by_uses_principal_uuid_when_available():
    principal = AuthPrincipal(id="22222222-2222-2222-2222-222222222222")
    assert resolve_created_by(principal, None) == "22222222-2222-2222-2222-222222222222"


def test_resolve_created_by_ignores_non_uuid_principal():
    principal = AuthPrincipal(id="api-key")
    assert resolve_created_by(principal, None) == SYSTEM_PRINCIPAL_ID


def test_get_config_invalid_path_returns_400(client):
    response = client.get("/config/bad path")
    assert response.status_code == 400
    assert response.json()["detail"] == "invalid path"


def test_get_secret_invalid_path_returns_400(client):
    response = client.get("/secret/bad path")
    assert response.status_code == 400
    assert response.json()["detail"] == "invalid path"


@patch("app.routes.secrets.resolve_created_by", lambda *_: "11111111-1111-1111-1111-111111111111")
@patch("app.routes.secrets.ensure_app")
@patch("app.routes.secrets.seal")
@patch("app.routes.secrets.pool")
def test_put_secret_success(mock_pool, mock_seal, mock_ensure_app, client):
    path = "service/api"
    payload = {"app_id": "service", "value": {"foo": "bar"}}
    actor_id = "11111111-1111-1111-1111-111111111111"
    nonce = b"nonce"
    ciphertext = b"ciphertext"
    mock_seal.return_value = (nonce, ciphertext)
    mock_ensure_app.side_effect = lambda *args, **kwargs: None

    mock_conn = MagicMock()
    mock_cur = MagicMock()
    mock_pool.connection.return_value.__enter__.return_value = mock_conn
    mock_conn.cursor.return_value.__enter__.return_value = mock_cur

    now = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    mock_cur.fetchone.side_effect = [
        {"app_name": "Service API"},
        {"id": 42},
        {"next_ver": 2},
        {"version": 2, "created_at": now},
    ]

    response = client.post(
        f"/secret/{path}",
        json=payload,
        headers={"X-Actor-Id": actor_id, "X-API-Key": "dummy"},
    )

    assert response.status_code == 201
    data = response.json()
    assert data["path"] == path
    assert data["version"] == 2
    assert data["value"] == payload["value"]
    assert data["created_at"] == now.isoformat()


@patch("app.routes.secrets.resolve_created_by", lambda *_: "11111111-1111-1111-1111-111111111111")
@patch("app.routes.secrets.ensure_app")
@patch("app.routes.secrets.seal")
@patch("app.routes.secrets.pool")
def test_put_secret_parent_item_missing(mock_pool, mock_seal, mock_ensure_app, client):
    path = "service/api"
    payload = {"app_id": "service", "value": {"foo": "bar"}}
    mock_ensure_app.side_effect = lambda *args, **kwargs: None

    mock_conn = MagicMock()
    mock_cur = MagicMock()
    mock_pool.connection.return_value.__enter__.return_value = mock_conn
    mock_conn.cursor.return_value.__enter__.return_value = mock_cur

    mock_cur.fetchone.side_effect = [
        {"app_name": "Service API"},
        None,
    ]

    response = client.post(
        f"/secret/{path}",
        json=payload,
        headers={"X-API-Key": "dummy"},
    )

    assert response.status_code == 500
    assert response.json()["detail"] == "Secret item not created"


@patch("app.routes.config.resolve_created_by", lambda *_: "11111111-1111-1111-1111-111111111111")
@patch("app.routes.config.ensure_app")
@patch("app.routes.config.pool")
def test_put_config_file_upload(mock_pool, mock_ensure_app, client):
    path = "app/config-file"
    mock_ensure_app.side_effect = lambda *args, **kwargs: None
    
    mock_conn = MagicMock()
    mock_cur = MagicMock()
    mock_pool.connection.return_value.__enter__.return_value = mock_conn
    mock_conn.cursor.return_value.__enter__.return_value = mock_cur
    
    now = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    mock_cur.fetchone.side_effect = [
        {"app_name": "My App"},
        None,
        {"id": 101, "version": 5, "created_at": now},
    ]
    
    # Fix 1: Use dict for form data
    data = {
        "appId": "myapp",
        "appName": "My App",
    }
    
    # Fix 2: Proper file tuple format
    files = {
        "file": ("cfg.txt", b"hello world", "text/plain")
    }
    
    # Fix 3: Add debug output
    response = client.post(
        f"/config/{path}/file",
        data=data,  # Changed from params list
        files=files,
        headers={"X-Actor-Id": "11111111-1111-1111-1111-111111111111", "X-API-Key": "dummy"},
    )
    
    # Add helpful error message
    if response.status_code != 201:
        print(f"Error Response: {response.text}")
        print(f"Status Code: {response.status_code}")
    
    assert response.status_code == 201, f"Expected 201, got {response.status_code}: {response.text}"
    assert response.json()["version"] == 5
    assert response.json()["path"] == path
