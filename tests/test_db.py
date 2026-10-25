import pytest
from datetime import datetime, timezone, timedelta
from sqlmodel import Session, select

from api.models import Finding, RuleAttempt, Deployment, Event, FindingStatus, get_utc_now
from api.lifecycle import calculate_mttp

def test_database_finding_crud(db_session: Session):
    # Create finding
    f = Finding(
        id="F-TEST-01",
        target="/login",
        parameter="username",
        type="sqli",
        severity="high",
        source="zap",
        description="SQL injection in login parameter",
        status=FindingStatus.NEW
    )
    db_session.add(f)
    db_session.commit()

    # Retrieve finding
    retrieved = db_session.get(Finding, "F-TEST-01")
    assert retrieved is not None
    assert retrieved.target == "/login"
    assert retrieved.status == FindingStatus.NEW
    assert retrieved.created_at is not None

def test_database_attempts_persistence(db_session: Session):
    f = Finding(
        id="F-TEST-02",
        target="/comment",
        parameter="text",
        type="xss",
        status=FindingStatus.PROTECTING
    )
    db_session.add(f)
    db_session.commit()

    # Add attempt 1 (failed)
    attempt1 = RuleAttempt(
        finding_id=f.id,
        attempt_no=1,
        strategy="strict",
        rule_text="SecRule ARGS:text '@rx <'",
        syntax_ok=True,
        attacks_blocked=5,
        attacks_total=5,
        users_ok=18,
        users_total=20,
        passed=False,
        failure_reason="Blocked user comment with bracket"
    )
    db_session.add(attempt1)
    db_session.commit()

    # Add attempt 2 (passed)
    attempt2 = RuleAttempt(
        finding_id=f.id,
        attempt_no=2,
        strategy="precise",
        rule_text="SecRule ARGS:text '@rx <script'",
        syntax_ok=True,
        attacks_blocked=5,
        attacks_total=5,
        users_ok=20,
        users_total=20,
        passed=True
    )
    db_session.add(attempt2)
    db_session.commit()

    # Query attempts for finding
    attempts = db_session.exec(select(RuleAttempt).where(RuleAttempt.finding_id == f.id)).all()
    assert len(attempts) == 2
    assert attempts[0].passed is False
    assert attempts[1].passed is True
    assert attempts[0].failure_reason is not None

def test_database_deployment_lifecycle_and_mttp(db_session: Session):
    created_time = datetime(2026, 10, 16, 10, 0, 0, tzinfo=timezone.utc)
    approved_time = datetime(2026, 10, 16, 10, 2, 30, tzinfo=timezone.utc)

    f = Finding(
        id="F-TEST-03",
        target="/login",
        parameter="user",
        type="sqli",
        status=FindingStatus.LIVE,
        created_at=created_time
    )
    db_session.add(f)
    db_session.commit()

    # Attempt
    att = RuleAttempt(
        finding_id=f.id,
        attempt_no=1,
        rule_text="SecRule...",
        passed=True
    )
    db_session.add(att)
    db_session.commit()

    # Deployment
    dep = Deployment(
        finding_id=f.id,
        attempt_id=att.id,
        approved_by="Alice Security",
        approved_at=approved_time
    )
    db_session.add(dep)
    db_session.commit()

    # Check MTTP
    mttp_str, mttp_sec = calculate_mttp(f, db_session)
    assert mttp_sec == 150 # 2 minutes 30 seconds
    assert mttp_str == "2m 30s"

def test_database_events(db_session: Session):
    evt = Event(
        method="POST",
        path="/login",
        query="username=admin",
        status_code=403,
        outcome="blocked",
        rule_id="F-001"
    )
    db_session.add(evt)
    db_session.commit()

    retrieved = db_session.exec(select(Event).where(Event.rule_id == "F-001")).first()
    assert retrieved is not None
    assert retrieved.outcome == "blocked"
    assert retrieved.status_code == 403
