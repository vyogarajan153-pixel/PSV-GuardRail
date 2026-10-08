from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health_check():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_events_endpoint():
    response = client.get("/api/events")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_alerts_endpoint():
    response = client.get("/api/alerts")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_incidents_endpoint():
    response = client.get("/api/incidents")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_endpoints_endpoint():
    response = client.get("/api/endpoints")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_dashboard_stats():
    response = client.get("/api/dashboard/stats")
    assert response.status_code == 200
    data = response.json()
    assert "cards" in data
    assert "severity" in data


def test_missing_alert_returns_404():
    response = client.get("/api/alerts/999999999")
    assert response.status_code == 404


def test_missing_event_returns_404():
    response = client.get("/api/events/999999999")
    assert response.status_code == 404


def test_missing_incident_returns_404():
    response = client.get("/api/incidents/999999999")
    assert response.status_code == 404
