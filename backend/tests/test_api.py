"""
Tests d'intégration pour les endpoints API WARDEN.
Utilise TestClient de FastAPI — pas besoin de serveur réel.
"""
import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "operational"
    assert response.json()["service"] == "WARDEN"


def test_verify_malformed_token():
    response = client.post("/v1/verify", json={"token": "not-a-jwt"})
    assert response.status_code == 200  # Toujours 200
    assert response.json()["valid"] is False
    assert response.json()["reason"] in ["MALFORMED", "UNKNOWN_OWNER"]


def test_register_agent_without_auth():
    response = client.post(
        "/v1/agents/register",
        json={"name": "test-bot"},
    )
    assert response.status_code == 401
