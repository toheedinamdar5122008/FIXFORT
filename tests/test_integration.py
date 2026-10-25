import time
import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select
from api.models import Finding, FindingStatus, Event
from api.shield_ctl import get_rules_dir

def test_full_e2e_protect_approve_retire_pipeline(client: TestClient, db_session: Session):
    # 1. Create finding F-001
    finding_data = {
        "id": "F-001",
        "target": "/login",
        "parameter": "username",
        "type": "sqli",
        "severity": "high",
        "source": "zap",
        "description": "Login query built by string concatenation"
    }
    res = client.post("/findings", json=finding_data)
    assert res.status_code == 201

    # 2. Trigger Protection Pipeline
    res = client.post("/protect/F-001")
    assert res.status_code == 202
    assert res.json()["status"] == "started"

    # Give background task a moment to complete practice attempts
    time.sleep(1.0)

    # 3. Poll status
    res = client.get("/status/F-001")
    assert res.status_code == 200
    status_data = res.json()
    assert status_data["status"] == FindingStatus.TESTED
    assert len(status_data["attempts"]) == 2
    
    # Attempt 1 should be strict (failing O'Brien test)
    att1 = status_data["attempts"][0]
    assert att1["strategy"] == "strict"
    assert att1["passed"] is False
    assert "O'Brien" in str(att1["failure_reason"])

    # Attempt 2 should be precise (passing all attacks and users)
    att2 = status_data["attempts"][1]
    assert att2["strategy"] == "precise"
    assert att2["passed"] is True
    assert att2["attacks_blocked"] == 5
    assert att2["users_ok"] == 20

    # 4. Human Approval
    res = client.post("/approve/F-001", json={"approved_by": "Lead DevSecOps"})
    assert res.status_code == 200
    assert res.json()["status"] == "success"

    # Confirm Live rule deployed
    live_rule_file = get_rules_dir("live") / "fixfort-F-001.conf"
    assert live_rule_file.exists()

    # 5. Check Protection Certificate
    res = client.get("/certificate/F-001")
    assert res.status_code == 200
    cert = res.json()
    assert cert["finding_id"] == "F-001"
    assert cert["approved_by"] == "Lead DevSecOps"
    assert cert["approved_at"] is not None
    assert cert["exam_attacks"] == "5/5"
    assert cert["exam_users"] == "20/20"

    # 6. Verify Fix and Retire (with mocked safe fixed app)
    from unittest.mock import patch
    with patch("api.lifecycle.run_exam") as mock_exam:
        mock_exam.return_value = {
            "attacks_blocked": 5,
            "attacks_total": 5,
            "users_ok": 20,
            "users_total": 20,
            "passed": True,
            "failures": []
        }
        res = client.post("/verify-fix/F-001")
        assert res.status_code == 200
        assert res.json()["status"] == "success"
        assert res.json()["details"]["retired"] is True

    # Rule must now be retired from live shield
    assert not live_rule_file.exists()

    # Check updated certificate
    res = client.get("/certificate/F-001")
    assert res.status_code == 200
    cert = res.json()
    assert cert["is_verified_and_retired"] is True
    assert cert["retired_at"] is not None
    assert cert["fix_verified_at"] is not None
