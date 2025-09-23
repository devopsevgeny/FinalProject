# python
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from .main import app, put_secret

@pytest.fixture
def client():
    return TestClient(app)

@patch("app.main.require_api_key", lambda: None)
@patch("app.main.seal")
@patch("app.main.pool")
def test_put_secret_success(mock_pool, mock_seal, client):
    # Arrange
    path = "service/api"
    payload = {"value": {"foo": "bar"}}
    actor_id = "11111111-1111-1111-1111-111111111111"
    nonce = b"nonce"
    ciphertext = b"ciphertext"
    mock_seal.return_value = (nonce, ciphertext)

    # Mock DB cursor and connection
    mock_conn = MagicMock()
    mock_cur = MagicMock()
    mock_pool.connection.return_value.__enter__.return_value = mock_conn
    mock_conn.cursor.return_value.__enter__.return_value = mock_cur

    # Simulate DB steps
    # 1. Insert parent item (no return)
    # 2. Lock parent row, return item id
    mock_cur.fetchone.side_effect = [
        {"id": 42},  # select id from core.secret_items
        {"mv": 1},   # select coalesce(max(version), 0)
        {"version": 2, "created_at": "2024-06-01T12:00:00"}  # returning version, created_at
    ]

    # Act
    response = client.post(
        f"/secret/{path}",
        json=payload,
        headers={"X-Actor-Id": actor_id, "X-API-Key": "dummy"}
    )

    # Assert
    assert response.status_code == 201
    data = response.json()
    assert data["path"] == path
    assert data["version"] == 2
    assert data["value"] == payload["value"]
    assert data["created_at"] == "2024-06-01T12:00:00"

@patch("app.main.require_api_key", lambda: None)
@patch("app.main.seal")
@patch("app.main.pool")
def test_put_secret_parent_item_missing(mock_pool, mock_seal, client):
    path = "service/api"
    payload = {"value": {"foo": "bar"}}
    mock_conn = MagicMock()
    mock_cur = MagicMock()
    mock_pool.connection.return_value.__enter__.return_value = mock_conn
    mock_conn.cursor.return_value.__enter__.return_value = mock_cur

    # Simulate parent item not found after insert/select
    mock_cur.fetchone.side_effect = [None]

    response = client.post(
        f"/secret/{path}",
        json=payload,
        headers={"X-API-Key": "dummy"}
    )
    assert response.status_code == 500
    assert response.json()["detail"] == "Secret item not created"