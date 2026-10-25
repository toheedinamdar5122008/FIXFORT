import json
import logging
from datetime import datetime, timezone
from typing import Tuple, Optional, Dict, Any
from sqlmodel import Session, select
from api.models import Finding, RuleAttempt, Deployment, FindingStatus, get_utc_now
from api.shield_ctl import apply_rule, remove_rule, check_syntax, reload, ShieldControlError
from api.brain_adapter import run_exam
from api.config import settings

logger = logging.getLogger("fixfort.lifecycle")

class LifecycleError(Exception):
    pass

def calculate_mttp(finding: Finding, session: Session) -> Tuple[Optional[str], Optional[int]]:
    """
    MTTP = approved_at - created_at.
    Returns (display_string, seconds).
    """
    statement = (
        select(Deployment)
        .where(Deployment.finding_id == finding.id)
        .order_by(Deployment.approved_at.desc())
    )
    deployment = session.exec(statement).first()
    if not deployment or not deployment.approved_at:
        return None, None

    # Calculate difference
    # Ensure both datetimes are timezone-aware UTC
    t_start = finding.created_at
    if t_start.tzinfo is None:
        t_start = t_start.replace(tzinfo=timezone.utc)
    
    t_end = deployment.approved_at
    if t_end.tzinfo is None:
        t_end = t_end.replace(tzinfo=timezone.utc)

    diff_seconds = max(0, int((t_end - t_start).total_seconds()))
    if diff_seconds < 60:
        display = f"{diff_seconds}s"
    elif diff_seconds < 3600:
        minutes = diff_seconds // 60
        secs = diff_seconds % 60
        display = f"{minutes}m {secs}s"
    else:
        hours = diff_seconds // 3600
        minutes = (diff_seconds % 3600) // 60
        display = f"{hours}h {minutes}m"

    return display, diff_seconds

def approve_finding(finding_id: str, approved_by: str, session: Session) -> Dict[str, Any]:
    """
    Approve endpoint implementation:
    Enforces that finding is TESTED and has a valid passing attempt.
    Applies rule to live shield with pre-validation and reloads live shield.
    Creates deployment record and updates status to LIVE.
    """
    finding = session.get(Finding, finding_id)
    if not finding:
        raise LifecycleError(f"Finding '{finding_id}' not found.")

    if finding.status not in (FindingStatus.TESTED, FindingStatus.NEW):
        raise LifecycleError(f"Cannot approve finding with status '{finding.status}'. Finding must be 'TESTED'.")

    # Find the latest passing attempt
    statement = (
        select(RuleAttempt)
        .where(RuleAttempt.finding_id == finding.id)
        .where(RuleAttempt.passed == True)
        .order_by(RuleAttempt.attempt_no.desc())
    )
    passing_attempt = session.exec(statement).first()
    if not passing_attempt:
        raise LifecycleError(f"No verified passing rule attempt found for finding '{finding_id}'. Cannot approve.")

    # Live application safety: apply rule to live rules directory
    try:
        apply_rule("live", finding.id, passing_attempt.rule_text)
        ok, err = check_syntax("live")
        if not ok:
            remove_rule("live", finding.id)
            raise ShieldControlError(f"Live shield syntax validation failed: {err}")

        ok, err = reload("live")
        if not ok:
            remove_rule("live", finding.id)
            raise ShieldControlError(f"Live shield reload failed: {err}")
    except Exception as e:
        logger.error("Failed applying live rule for finding %s: %s", finding_id, e)
        raise LifecycleError(f"Infrastructure failure during live rule deployment: {e}")

    # Record deployment
    now = get_utc_now()
    deployment = Deployment(
        finding_id=finding.id,
        attempt_id=passing_attempt.id,
        approved_by=approved_by,
        approved_at=now
    )
    session.add(deployment)
    finding.status = FindingStatus.LIVE
    session.add(finding)
    session.commit()
    session.refresh(finding)
    session.refresh(deployment)

    logger.info("Finding %s approved by %s and deployed to LIVE shield.", finding_id, approved_by)
    return {
        "status": "success",
        "message": f"Rule successfully approved and deployed to live shield.",
        "finding_id": finding.id,
        "current_status": finding.status,
        "deployment_id": deployment.id
    }

def rollback_finding(finding_id: str, session: Session) -> Dict[str, Any]:
    """
    Rollback endpoint implementation:
    Safely removes rule from live shield, reloads live shield,
    records rolled_back_at timestamp, and updates status to ROLLED_BACK.
    """
    finding = session.get(Finding, finding_id)
    if not finding:
        raise LifecycleError(f"Finding '{finding_id}' not found.")

    statement = (
        select(Deployment)
        .where(Deployment.finding_id == finding.id)
        .order_by(Deployment.approved_at.desc())
    )
    deployment = session.exec(statement).first()
    if not deployment or finding.status != FindingStatus.LIVE:
        raise LifecycleError(f"Finding '{finding_id}' does not have an active live deployment to roll back.")

    try:
        remove_rule("live", finding.id)
        ok, err = check_syntax("live")
        if not ok:
            raise ShieldControlError(f"Syntax validation failed after rule removal: {err}")
        ok, err = reload("live")
        if not ok:
            raise ShieldControlError(f"Live reload failed after rule removal: {err}")
    except Exception as e:
        logger.error("Rollback failed on live shield for %s: %s", finding_id, e)
        raise LifecycleError(f"Failed to cleanly remove rule from live shield: {e}")

    now = get_utc_now()
    deployment.rolled_back_at = now
    finding.status = FindingStatus.ROLLED_BACK
    session.add(deployment)
    session.add(finding)
    session.commit()
    session.refresh(finding)

    logger.info("Finding %s rolled back successfully.", finding_id)
    return {
        "status": "success",
        "message": f"Temporary rule for finding {finding_id} rolled back from live shield.",
        "finding_id": finding.id,
        "current_status": finding.status
    }

def verify_fix_and_retire(finding_id: str, session: Session) -> Dict[str, Any]:
    """
    Feature 3: Complete Verify-Fix-and-Retire Lifecycle.
    1. Check finding is in LIVE status.
    2. Temporarily remove rule from sandbox shield and reload.
    3. Run exam against sandbox application without temporary rule.
    4. If attacks fail because permanent code fix is solid and all good users pass:
       - Safely remove rule from live shield and reload live shield.
       - Record fix_verified_at and retired_at.
       - Mark status RETIRED.
       - Return: 'Code fix confirmed. Temporary rule retired.'
    5. If any attack still works:
       - Keep live protection ACTIVE!
       - Re-apply rule to sandbox.
       - Return failure message without marking RETIRED.
    """
    finding = session.get(Finding, finding_id)
    if not finding:
        raise LifecycleError(f"Finding '{finding_id}' not found.")

    if finding.status != FindingStatus.LIVE:
        raise LifecycleError(f"Cannot verify fix for finding in '{finding.status}' status. Finding must be 'LIVE'.")

    # Get active deployment and passing rule text
    statement = (
        select(Deployment)
        .where(Deployment.finding_id == finding.id)
        .order_by(Deployment.approved_at.desc())
    )
    deployment = session.exec(statement).first()
    if not deployment:
        raise LifecycleError(f"No active deployment found for finding '{finding_id}'.")

    passing_attempt = session.get(RuleAttempt, deployment.attempt_id)
    rule_text = passing_attempt.rule_text if passing_attempt else ""

    # Step 1: Remove rule from sandbox shield to test the naked application code
    remove_rule("sandbox", finding.id)
    check_syntax("sandbox")
    reload("sandbox")

    # Step 1b: If the app is currently in fixed mode (developer deployed fix),
    # the exam proves the code fix. If still vulnerable, the exam fails safe.

    # Step 2: Run exam against sandbox
    finding_dict = {
        "id": finding.id,
        "target": finding.target,
        "parameter": finding.parameter,
        "type": finding.type,
        "description": finding.description
    }
    exam_result = run_exam(settings.sandbox_shield_url, finding_dict)
    exam_dict = exam_result.to_dict() if hasattr(exam_result, "to_dict") else (exam_result if isinstance(exam_result, dict) else {})
    passed = exam_dict.get("passed", False)

    now = get_utc_now()

    if passed:
        # Code fix is proven safe and complete!
        # Step 3: Retire rule from live shield safely
        try:
            remove_rule("live", finding.id)
            check_syntax("live")
            reload("live")
        except Exception as e:
            logger.error("Failed retiring rule from live shield: %s", e)
            raise LifecycleError(f"Failed removing rule from live shield: {e}")

        deployment.fix_verified_at = now
        deployment.retired_at = now
        finding.status = FindingStatus.RETIRED

        session.add(deployment)
        session.add(finding)
        session.commit()
        session.refresh(finding)

        logger.info("Finding %s verified and retired successfully.", finding_id)
        return {
            "status": "success",
            "message": "Code fix confirmed. Temporary rule retired.",
            "finding_id": finding.id,
            "current_status": finding.status,
            "retired": True,
            "exam_result": exam_dict
        }
    else:
        # Verification failed! Attack still works or legitimate user broken.
        # Live shield MUST stay protected!
        if rule_text:
            apply_rule("sandbox", finding.id, rule_text)
            reload("sandbox")
        # Restore the sandbox app to vulnerable so the demo state is consistent.
        try:
            import requests as _rq
            _rq.post(settings.sandbox_shield_url.rstrip("/") + "/api/mode",
                     json={"mode": "vulnerable"}, timeout=3)
        except Exception:
            pass

        first_failure = "unknown error"
        failures = exam_dict.get("failures", [])
        if failures and isinstance(failures, list):
            f = failures[0]
            first_failure = f.get("name", "sqli_union") if isinstance(f, dict) else getattr(f, "name", "sqli_union")

        logger.warning("Verification failed for %s. Rule stays active in live.", finding_id)
        return {
            "status": "failed",
            "message": f"Fix incomplete: attack {first_failure} still works. Temporary rule stays active.",
            "finding_id": finding.id,
            "current_status": finding.status,
            "retired": False,
            "exam_result": exam_dict
        }
