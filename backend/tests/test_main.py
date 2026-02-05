from fastapi.testclient import TestClient
from main import app
import pytest
from unittest.mock import MagicMock, patch

client = TestClient(app)

def test_read_root():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"status": "online", "message": "PQC Assessment API Ready"}

@patch("main.redis_client")
def test_trigger_scan(mock_redis):
    # Mock Redis lpush to avoid actual connection
    mock_redis.lpush.return_value = 1
    
    response = client.post("/scan", json={"repo_path": "/tmp/test-repo"})
    
    assert response.status_code == 200
    data = response.json()
    assert "job_id" in data
    assert data["status"] == "queued"
    
    # Verify Redis was called
    mock_redis.lpush.assert_called_once()
    args, _ = mock_redis.lpush.call_args
    assert args[0] == "pqc_tasks"
    assert "job_id" in args[1]

@patch("main.redis_client")
def test_redis_failure(mock_redis):
    # Simulate Redis failure
    mock_redis.lpush.side_effect = Exception("Connection Error")
    
    # Depending on how the app handles generic exceptions (FastAPI default is 500)
    # The app actually catches redis.ConnectionError, so let's mock that specifically if possible
    # But usually TestClient will propagate exceptions unless handled.
    # update: app catches redis.ConnectionError and raises 500.
    
    import redis
    mock_redis.lpush.side_effect = redis.ConnectionError("Boom")
    
    response = client.post("/scan", json={"repo_path": "/tmp/test-repo"})
    assert response.status_code == 500
    assert response.json()["detail"] == "Could not connect to Redis Task Queue"
