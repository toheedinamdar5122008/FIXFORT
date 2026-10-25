import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from api.models import Finding, RuleAttempt, Deployment, FindingStatus
from api.shield_ctl import get_rules_dir

def test_scenario_1_successful_protection_and_approval(client: TestClient, db_session: Session):
    # 1. Create finding
    f = Finding(
        id="F-SCENARIO-1",
        target="/login",
        parameter="username",
        type="sqli",
        status=FindingStatus.NEW
    )
    db_session.add(f)
    db_session.commit()

    # 2. Simulate Practice Room attempt completion
    att1 = RuleAttempt(
        finding_id=f.id,
        attempt_no=1,
        strategy="strict",
        rule_text="SecRule ARGS:username '@rx .'",
        attacks_blocked=5,
        attacks_total=5,
        users_ok=19,
        users_total=20,
        passed=False,
        failure_reason="Blocked user O'Brien"
    )
    att2 = RuleAttempt(
        finding_id=f.id,
        attempt_no=2,
        strategy="precise",
        rule_text="SecRule ARGS:username '@rx (?i)union\\s+select'",
        attacks_blocked=5,
        attacks_total=5,
        users_ok=20,
        users_total=20,
        passed=True
    )
    f.status = FindingStatus.TESTED
    db_session.add(att1)
    db_session.add(att2)
    db_session.add(f)
    db_session.commit()

    # 3. Approve Rule
    res = client.post(f"/approve/{f.id}", json={"approved_by": "Senior DevSecOps"})
    assert res.status_code == 200
    assert res.json()["status"] == "success"

    # Confirm status in DB is LIVE
    db_session.refresh(f)
    assert f.status == FindingStatus.LIVE

    # Confirm rule was installed in rules-live/
    live_rule_file = get_rules_dir("live") / f"fixfort-{f.id}.conf"
    assert live_rule_file.exists()
    assert "union\\s+select" in live_rule_file.read_text(encoding="utf-8")

def test_scenario_2_failed_verification_preserves_live_shield(client: TestClient, db_session: Session):
    # Setup live deployed finding
    f = Finding(id="F-SCENARIO-2", target="/login", parameter="username", type="sqli", status=FindingStatus.LIVE)
    db_session.add(f)
    db_session.commit()

    att = RuleAttempt(finding_id=f.id, attempt_no=1, rule_text="SecRule ...", passed=True)
    db_session.add(att)
    db_session.commit()

    dep = Deployment(finding_id=f.id, attempt_id=att.id, approved_by="Admin")
    db_session.add(dep)
    db_session.commit()

    # Mock run_exam to simulate incomplete permanent fix (attacks still work!)
    with patch("api.lifecycle.run_exam") as mock_exam:
        mock_exam.return_value = {
            "attacks_blocked": 0,
            "attacks_total": 5,
            "users_ok": 20,
            "users_total": 20,
            "passed": False,
            "failures": [{"kind": "attack", "name": "sqli_union", "got": 200}]
        }

        res = client.post(f"/verify-fix/{f.id}")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "failed"
        assert "Fix incomplete" in data["message"]
        assert data["details"]["retired"] is False

    # Confirm finding status is NOT RETIRED, remains LIVE
    db_session.refresh(f)
    assert f.status == FindingStatus.LIVE

def test_scenario_3_successful_verification_and_retire(client: TestClient, db_session: Session):
    # Setup live deployed finding
    f = Finding(id="F-SCENARIO-3", target="/login", parameter="username", type="sqli", status=FindingStatus.LIVE)
    db_session.add(f)
    db_session.commit()

    att = RuleAttempt(finding_id=f.id, attempt_no=1, rule_text="SecRule ...", passed=True)
    db_session.add(att)
    db_session.commit()

    dep = Deployment(finding_id=f.id, attempt_id=att.id, approved_by="Admin")
    db_session.add(dep)
    db_session.commit()

    # Mock run_exam to simulate permanent fix works (attacks fail on code level)
    with patch("api.lifecycle.run_exam") as mock_exam:
        mock_exam.return_value = {
            "attacks_blocked": 5,
            "attacks_total": 5,
            "users_ok": 20,
            "users_total": 20,
            "passed": True,
            "failures": []
        }

        res = client.post(f"/verify-fix/{f.id}")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert "Code fix confirmed. Temporary rule retired." in data["message"]
        assert data["details"]["retired"] is True

    # Confirm finding status is RETIRED and timestamps are stored
    db_session.refresh(f)
    assert f.status == FindingStatus.RETIRED
    db_session.refresh(dep)
    assert dep.fix_verified_at is not None
    assert dep.retired_at is not None

def test_scenario_4_rollback(client: TestClient, db_session: Session):
    f = Finding(id="F-SCENARIO-4", target="/login", parameter="username", type="sqli", status=FindingStatus.LIVE)
    db_session.add(f)
    db_session.commit()

    att = RuleAttempt(finding_id=f.id, attempt_no=1, rule_text="SecRule ...", passed=True)
    db_session.add(att)
    db_session.commit()

    dep = Deployment(finding_id=f.id, attempt_id=att.id, approved_by="Admin")
    db_session.add(dep)
    db_session.commit()

    # Roll back
    res = client.post(f"/rollback/{f.id}")
    assert res.status_code == 200
    assert res.json()["status"] == "success"

    # Confirm status is ROLLED_BACK
    db_session.refresh(f)
    assert f.status == FindingStatus.ROLLED_BACK
    db_session.refresh(dep)
    assert dep.rolled_back_at is not None

def test_scenario_5_safety_rejects_untested_or_failed_rule(client: TestClient, db_session: Session):
    # Finding with only a failed attempt
    f = Finding(id="F-SCENARIO-5", target="/login", parameter="username", type="sqli", status=FindingStatus.PROTECTING)
    db_session.add(f)
    db_session.commit()

    att = RuleAttempt(finding_id=f.id, attempt_no=1, rule_text="SecRule ...", passed=False)
    db_session.add(att)
    db_session.commit()

    # Attempt to approve
    res = client.post(f"/approve/{f.id}")
    assert res.status_code == 400
    assert "Cannot approve" in res.json()["detail"]
