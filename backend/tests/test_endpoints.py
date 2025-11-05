from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

# FastAPI's TestClient relies on Starlette's optional HTTPX dependency. When HTTPX
# is not installed we skip the module and point contributors to the dev
# requirements file that installs it.
pytest.importorskip(
    "httpx",
    reason=(
        "fastapi.testclient requires httpx; install backend test extras with "
        "`pip install -r backend/requirements-dev.txt`"
    ),
)

from fastapi.testclient import TestClient

from app.auth_mode import AUTH_DEP
from app.main import app


@pytest.fixture(autouse=True)
def override_auth_dependency():
    """Bypass authentication for unit tests."""
    app.dependency_overrides[AUTH_DEP] = lambda: None
    yield
    app.dependency_overrides.pop(AUTH_DEP, None)


@pytest.fixture
def client():
    return TestClient(app)


@patch("app.routes.secrets.resolve_created_by", lambda *_: "actor-1")
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


@patch("app.routes.secrets.resolve_created_by", lambda *_: "actor-1")
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


@patch("app.routes.config.resolve_created_by", lambda *_: "actor-1")
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
    
    data = {
        "appId": "myapp",
        "appName": "My App",
    }

    files = {
        "file": ("cfg.txt", b"hello world", "text/plain")
    }

    response = client.post(
        f"/config/{path}/file",
        data=data,
        files=files,
        headers={"X-Actor-Id": "actor-1", "X-API-Key": "dummy"},
    )

    assert response.status_code == 201

    body = response.json()
    assert body["path"] == path
    assert body["version"] == 5
    assert body["app_id"] == "myapp"
    assert body["app_name"] == "My App"
    assert body["file_name"] == "cfg.txt"
    assert body["content_type"] == "text/plain"
    assert body["file_size"] == len(files["file"][1])
    assert body["created_at"] == now.isoformat()
