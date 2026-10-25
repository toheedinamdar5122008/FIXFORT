import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session
from api.models import Finding, FindingStatus

def test_api_health_and_ready(client: TestClient):
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json()["status"] == "healthy"

    res = client.get("/ready")
    assert res.status_code == 200
    assert "database" in res.json()

def test_api_findings_crud_and_validation(client: TestClient):
    # Missing required field 'target' -> 422
    bad_payload = {"parameter": "test"}
    res = client.post("/findings", json=bad_payload)
    assert res.status_code == 422

    # Valid finding creation
    payload = {
        "id": "F-001",
        "target": "/login",
        "parameter": "username",
        "type": "sqli",
        "severity": "high",
        "source": "manual",
        "description": "SQL injection in login"
    }
    res = client.post("/findings", json=payload)
    assert res.status_code == 201
    data = res.json()
    assert data["id"] == "F-001"
    assert data["status"] == FindingStatus.NEW

    # List findings
    res = client.get("/findings")
    assert res.status_code == 200
    findings = res.json()
    assert len(findings) >= 1
    assert any(f["id"] == "F-001" for f in findings)

def test_api_zap_export_import(client: TestClient):
    zap_payload = {
        "site": "http://victim-live:5000",
        "alerts": [
            {
                "pluginId": "40018",
                "name": "SQL Injection",
                "riskdesc": "High (Medium)",
                "uri": "http://victim-live:5000/login",
                "param": "username",
                "desc": "SQL injection in login"
            }
        ]
    }
    res = client.post("/findings", json=zap_payload)
    assert res.status_code == 201
    data = res.json()
    assert "ZAP-" in data["id"]
    assert data["target"] == "/login"

def test_api_status_endpoint_nonexistent(client: TestClient):
    res = client.get("/status/NONEXISTENT-99")
    assert res.status_code == 404

def test_api_attack_helper_allowlist(client: TestClient):
    # Disallowed attack name -> 400 Bad Request
    res = client.post("/attack/rm_rf_root")
    assert res.status_code == 400
    assert "not in the allowlist" in res.json()["detail"]

    # Allowed attack name
    res = client.post("/attack/sqli_tautology")
    assert res.status_code == 200
    data = res.json()
    assert data["attack_name"] == "sqli_tautology"
    assert "response_status" in data

def test_api_fix_guidance(client: TestClient, db_session: Session):
    f = Finding(id="F-FIX-01", target="/login", parameter="username", type="sqli")
    db_session.add(f)
    db_session.commit()

    res = client.get("/fix/F-FIX-01")
    assert res.status_code == 200
    data = res.json()
    assert "before" in data
    assert "after" in data
    assert "explanation" in data

def test_api_reset(client: TestClient):
    res = client.post("/reset")
    assert res.status_code == 200
    assert res.json()["status"] == "reset"
