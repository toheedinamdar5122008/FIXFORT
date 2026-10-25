import json
import logging
import requests
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from pydantic import BaseModel

from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, Query, status, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import Session, select

from api.config import settings
from api.db import init_db, get_session, reset_db, engine
import api.db
from api.models import Finding, RuleAttempt, Deployment, Event, FindingStatus, get_utc_now
from api.schemas import (
    FindingCreate, FindingResponse, RuleAttemptResponse, FindingStatusResponse,
    ApproveRequest, ActionResponse, EventResponse, CertificateResponse, AttackHelperResponse,
    SentinelReviewResponse
)
from api.shield_ctl import apply_rule, remove_rule, check_syntax, reload, clear_all_rules
from api.events import event_reader
from api.lifecycle import calculate_mttp, approve_finding, rollback_finding, verify_fix_and_retire, LifecycleError
from api.brain_adapter import run_practice, suggest_fix, HAS_REAL_BRAIN
from api.agent37 import review_with_agent37
from api.seed import seed_sample_findings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("fixfort.api")

# In-memory tracking of active background protection runs, steps, and generations
ACTIVE_PROTECT_RUNS: set[str] = set()
ACTIVE_PIPELINE_STEPS: dict[str, str] = {}
PROTECT_GENERATION: dict[str, int] = {}
SENTINEL_REVIEWS: dict[str, dict] = {}

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize DB tables and seed sample finding
    init_db()
    seed_sample_findings()
    # Start live shield event reader
    event_reader.start()
    logger.info("FixFort Platform API initialized.")
    yield
    # Shutdown: Stop event reader
    event_reader.stop()
    logger.info("FixFort Platform API stopped.")

app = FastAPI(
    title="FixFort Platform API",
    description="The Fort Between Vulnerability and Resolution — Temporary Protection and Verification Platform",
    version="1.0.0",
    lifespan=lifespan
)

# CORS configuration allowing requests from dashboard origins without wildcard '*'
allowed_origins_raw = ["http://localhost:5173", "http://localhost:3000"] + settings.cors_origins
cors_origins = [origin for origin in dict.fromkeys(allowed_origins_raw) if origin != "*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    # Accept the dev dashboard on ANY local port (Vite may pick 5173, 5174, …),
    # so a port shift never forces the UI into offline mode. Never the public web.
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(:\d+)?",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------------------------------------------------------
# 1. Health & Observability Endpoints
# ------------------------------------------------------------------------------
@app.get("/", summary="FixFort Mission Control Gateway", response_model=None)
def root_endpoint(request: Request):
    accept_header = request.headers.get("accept", "")
    if "text/html" not in accept_header and "application/json" in accept_header:
        return {
            "name": "FixFort Platform API",
            "version": "1.0.0",
            "status": "online",
            "motto": "The AI suggests, the Practice Room proves, the human decides, and nothing stays temporary forever.",
            "endpoints": {
                "swagger_docs": "/docs",
                "redoc": "/redoc",
                "health": "/health",
                "ready": "/ready",
                "findings": "/findings",
                "events": "/events",
                "victim_app": "http://localhost:5000/login"
            }
        }
    
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>FixFort — Mission Control Gateway</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #0B0F17;
      --surface: #121A26;
      --surface-raised: #18222F;
      --border: #1E2A3A;
      --text: #E6EDF3;
      --muted: #8B98A9;
      --cyan: #22D3EE;
      --green: #22C55E;
      --amber: #F59E0B;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg);
      color: var(--text);
      font-family: 'Inter', -apple-system, sans-serif;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 40px 20px;
      background-image: radial-gradient(rgba(34, 211, 238, 0.04) 1px, transparent 1px);
      background-size: 28px 28px;
    }
    .container { width: 100%; max-width: 900px; }
    header {
      margin-bottom: 32px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid var(--border);
      padding-bottom: 24px;
    }
    .brand { display: flex; align-items: center; gap: 12px; }
    .logo-badge {
      background: rgba(34, 211, 238, 0.15);
      border: 1px solid var(--cyan);
      color: var(--cyan);
      font-weight: 700;
      padding: 6px 14px;
      border-radius: 8px;
      font-size: 18px;
      letter-spacing: 0.05em;
    }
    h1 { font-size: 24px; font-weight: 700; }
    .motto { color: var(--muted); font-size: 14px; margin-top: 4px; }
    .status-pills { display: flex; gap: 10px; }
    .pill {
      font-size: 12px;
      padding: 6px 12px;
      border-radius: 20px;
      display: flex;
      align-items: center;
      gap: 6px;
      background: var(--surface);
      border: 1px solid var(--border);
    }
    .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--green); box-shadow: 0 0 8px var(--green); }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 20px;
      margin-bottom: 32px;
    }
    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 24px;
      transition: all 0.2s ease;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }
    .card:hover {
      background: var(--surface-raised);
      border-color: var(--cyan);
      transform: translateY(-2px);
    }
    .card h3 { font-size: 17px; margin-bottom: 8px; color: var(--text); }
    .card p { color: var(--muted); font-size: 13.5px; line-height: 1.5; margin-bottom: 20px; }
    .btn {
      display: inline-block;
      text-decoration: none;
      font-size: 13px;
      font-weight: 600;
      padding: 9px 16px;
      border-radius: 6px;
      text-align: center;
      transition: all 0.2s ease;
    }
    .btn-primary { background: var(--cyan); color: #000; }
    .btn-primary:hover { opacity: 0.9; box-shadow: 0 0 12px rgba(34, 211, 238, 0.4); }
    .btn-secondary { background: transparent; border: 1px solid var(--border); color: var(--text); }
    .btn-secondary:hover { border-color: var(--muted); background: rgba(255,255,255,0.03); }
    .notice {
      background: rgba(245, 158, 11, 0.08);
      border: 1px solid rgba(245, 158, 11, 0.3);
      padding: 16px 20px;
      border-radius: 8px;
      color: #FBBF24;
      font-size: 13px;
      line-height: 1.6;
    }
    code { font-family: 'JetBrains Mono', monospace; font-size: 12px; color: var(--cyan); }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="brand">
        <span class="logo-badge">FIXFORT</span>
        <div>
          <h1>Mission Control Gateway</h1>
          <p class="motto">&ldquo;The AI suggests, the Practice Room proves, the human decides, and nothing stays temporary forever.&rdquo;</p>
        </div>
      </div>
      <div class="status-pills">
        <div class="pill"><span class="dot"></span> API Active (Port 8000)</div>
      </div>
    </header>

    <div class="grid">
      <div class="card">
        <div>
          <h3>Interactive API Docs</h3>
          <p>Explore and test all Person B REST endpoints interactively via Swagger UI.</p>
        </div>
        <a href="/docs" class="btn btn-primary">Open Swagger UI &rarr;</a>
      </div>

      <div class="card">
        <div>
          <h3>ReDoc Specification</h3>
          <p>Comprehensive OpenAPI contracts, request/response models, and status codes.</p>
        </div>
        <a href="/redoc" class="btn btn-secondary">Open ReDoc &rarr;</a>
      </div>

      <div class="card">
        <div>
          <h3>Findings & MTTP Feed</h3>
          <p>Inspect active findings and Mean Time to Protection metrics in JSON format.</p>
        </div>
        <a href="/findings" class="btn btn-secondary">View /findings &rarr;</a>
      </div>

      <div class="card">
        <div>
          <h3>Platform Readiness Probe</h3>
          <p>Deep health check across database, shields, and event reader.</p>
        </div>
        <a href="/ready" class="btn btn-secondary">Check /ready &rarr;</a>
      </div>

      <div class="card">
        <div>
          <h3>Demonstration Clinic Portal</h3>
          <p>The victim website running on Port 5000 with vulnerable and fixed modes.</p>
        </div>
        <a href="http://localhost:5000/login" target="_blank" class="btn btn-primary">Open Clinic Portal &rarr;</a>
      </div>

      <div class="card">
        <div>
          <h3>Live Threat Feed</h3>
          <p>Real-time stream of HTTP requests passing through the live shield.</p>
        </div>
        <a href="/events" class="btn btn-secondary">View /events &rarr;</a>
      </div>
    </div>

    <div class="notice">
      <strong>Architecture Note:</strong> FixFort Backend API is serving on port <code>8000</code>. When Docker is active, shields reverse-proxy incoming traffic via port <code>8080</code> (Live) and <code>8081</code> (Sandbox). The React Dashboard (Person C) connects directly to these endpoints via <code>CORS</code>.
    </div>
  </div>
</body>
</html>
"""
    return HTMLResponse(content=html_content, status_code=200)

@app.get("/health", summary="Basic health probe")
def health_check():
    return {
        "status": "healthy",
        "service": "fixfort-api",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@app.get("/ready", summary="Detailed platform readiness check")
def readiness_check(session: Session = Depends(get_session)):
    # 1. Check Database
    db_ok = False
    try:
        session.exec(select(Finding).limit(1))
        db_ok = True
    except Exception as e:
        logger.error("Readiness check: DB error: %s", e)

    # 2. Check Live Shield
    live_shield_ok = False
    try:
        r = requests.get(f"{settings.live_shield_url}/health", timeout=0.2)
        live_shield_ok = (r.status_code < 500)
    except Exception:
        live_shield_ok = False

    # 3. Check Sandbox Shield
    sandbox_shield_ok = False
    try:
        r = requests.get(f"{settings.sandbox_shield_url}/health", timeout=0.2)
        sandbox_shield_ok = (r.status_code < 500)
    except Exception:
        sandbox_shield_ok = False

    return {
        "status": "ready" if db_ok else "degraded",
        "database": "connected" if db_ok else "unreachable",
        "live_shield": "reachable" if live_shield_ok else "offline",
        "sandbox_shield": "reachable" if sandbox_shield_ok else "offline",
        "event_reader_running": event_reader.running,
        "brain_module": "real" if HAS_REAL_BRAIN else "adapter_fallback",
        "agent37_sentinel": {
            "instance_id": settings.agent37_instance_id,
            "base_url": settings.agent37_base_url,
            "configured": bool(settings.agent37_api_key and settings.agent37_api_key not in ("your_agent37_api_key_here", "CHANGE_ME", "none")),
        },
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

# ------------------------------------------------------------------------------
# 2. Findings Endpoints
# ------------------------------------------------------------------------------
@app.get("/findings", response_model=List[FindingResponse], summary="List all findings with MTTP")
def list_findings(session: Session = Depends(get_session)):
    findings = session.exec(select(Finding).order_by(Finding.created_at.desc())).all()
    results = []
    for f in findings:
        mttp_str, mttp_sec = calculate_mttp(f, session)
        results.append(FindingResponse(
            id=f.id,
            target=f.target,
            parameter=f.parameter,
            type=f.type,
            severity=f.severity,
            source=f.source,
            description=f.description,
            status=f.status,
            created_at=f.created_at,
            mttp=mttp_str,
            mttp_seconds=mttp_sec
        ))
    return results

@app.post("/findings", response_model=FindingResponse, status_code=status.HTTP_201_CREATED, summary="Import a finding (JSON or ZAP export)")
def create_finding(payload: Dict[str, Any], session: Session = Depends(get_session)):
    # Check if payload is a ZAP scan export format
    if "alerts" in payload:
        alerts = payload.get("alerts", [])
        if not alerts:
            raise HTTPException(status_code=400, detail="ZAP export contains no alerts.")
        first_alert = alerts[0]
        f_id = f"ZAP-{first_alert.get('pluginId', '001')}"
        target = first_alert.get("uri", "/login")
        if "://" in target:
            target = "/" + "/".join(target.split("://")[1].split("/")[1:])
        param = first_alert.get("param", "input")
        vuln_type = "sqli" if "sql" in first_alert.get("name", "").lower() else "xss"
        desc = first_alert.get("desc", first_alert.get("name", "Vulnerability"))
        severity = first_alert.get("riskdesc", "High").split()[0].lower()
        source = "zap"
    else:
        # Standard Finding format
        f_id = payload.get("id") or f"F-{int(datetime.now(timezone.utc).timestamp()) % 1000:03d}"
        target = payload.get("target")
        param = payload.get("parameter")
        vuln_type = payload.get("type", "sqli")
        severity = payload.get("severity", "high")
        source = payload.get("source", "manual")
        desc = payload.get("description", "")

    if not target or not param:
        raise HTTPException(status_code=422, detail="Both 'target' and 'parameter' are required.")

    # Prevent accidental duplicates
    existing = session.get(Finding, f_id)
    if existing:
        mttp_str, mttp_sec = calculate_mttp(existing, session)
        return FindingResponse(
            id=existing.id,
            target=existing.target,
            parameter=existing.parameter,
            type=existing.type,
            severity=existing.severity,
            source=existing.source,
            description=existing.description,
            status=existing.status,
            created_at=existing.created_at,
            mttp=mttp_str,
            mttp_seconds=mttp_sec
        )

    finding = Finding(
        id=f_id,
        target=target,
        parameter=param,
        type=vuln_type,
        severity=severity,
        source=source,
        description=desc,
        status=FindingStatus.NEW,
        created_at=get_utc_now()
    )
    session.add(finding)
    session.commit()
    session.refresh(finding)

    return FindingResponse(
        id=finding.id,
        target=finding.target,
        parameter=finding.parameter,
        type=finding.type,
        severity=finding.severity,
        source=finding.source,
        description=finding.description,
        status=finding.status,
        created_at=finding.created_at,
        mttp=None,
        mttp_seconds=None
    )

# ------------------------------------------------------------------------------
# 3. Practice Room & Protection Pipeline
# ------------------------------------------------------------------------------
def _background_practice_task(finding_id: str):
    """Executes the Practice Room loop in the background and saves evidence."""
    logger.info("Starting background practice task for finding %s", finding_id)
    my_gen = PROTECT_GENERATION.get(finding_id, 1)
    try:
        with Session(api.db.engine) as session:
            finding = session.get(Finding, finding_id)
            if not finding:
                return

            def on_step_callback(step_name: str, step_data: Dict[str, Any]):
                """Invoked by Person A's run_practice on every attempt/exam milestone."""
                logger.debug("Practice step for %s [%s]: %s", finding_id, step_name, step_data)
                # Drop stale executions
                if PROTECT_GENERATION.get(finding_id) != my_gen:
                    logger.info("Aborting stale practice task for %s (generation mismatch)", finding_id)
                    return

                # Real-time active step tracking for polling clients
                s_name = str(step_name).lower()
                if s_name in ("analyze", "start"):
                    ACTIVE_PIPELINE_STEPS[finding_id] = "analyze"
                elif s_name in ("generate", "retry", "fallback"):
                    ACTIVE_PIPELINE_STEPS[finding_id] = "generate"
                elif s_name == "syntax":
                    ACTIVE_PIPELINE_STEPS[finding_id] = "syntax"
                elif s_name == "exam":
                    ACTIVE_PIPELINE_STEPS[finding_id] = "exam"
                elif s_name == "done":
                    if step_data.get("status") == "TESTED":
                        ACTIVE_PIPELINE_STEPS[finding_id] = "approve"
                    else:
                        ACTIVE_PIPELINE_STEPS[finding_id] = "failed"

                if step_name == "result":
                    _a = step_data.get("attempt_no", step_data.get("attempt", 1))
                    attempt_no = _a if isinstance(_a, int) else 99
                    strategy = step_data.get("strategy", "strict")
                    proposal = step_data.get("proposal")
                    rule_text = step_data.get("rule", "")
                    syntax_ok = step_data.get("syntax_ok")
                    if syntax_ok is None:
                        syntax_ok = True
                    exam = step_data.get("exam", {})

                    # Ensure proposal is never None and maps incoming source, rule_id, and pattern
                    if not proposal or not isinstance(proposal, dict):
                        proposal = {
                            "target": step_data.get("target", finding.target),
                            "parameter": step_data.get("parameter", finding.parameter),
                            "strategy": strategy,
                            "pattern": step_data.get("pattern", ""),
                            "source": step_data.get("source", finding.source or "brain"),
                            "rule_id": step_data.get("rule_id", 100000 + attempt_no),
                            "reason": step_data.get("reason", f"FixFort {strategy} protection")
                        }
                    else:
                        proposal = dict(proposal)
                        if "pattern" in step_data and "pattern" not in proposal:
                            proposal["pattern"] = step_data["pattern"]
                        if "source" in step_data and "source" not in proposal:
                            proposal["source"] = step_data["source"]
                        elif "source" not in proposal:
                            proposal["source"] = finding.source or "brain"
                        if "rule_id" in step_data and "rule_id" not in proposal:
                            proposal["rule_id"] = step_data["rule_id"]

                    proposal_json_str = step_data.get("proposal_json") or json.dumps(proposal)

                    # Persist attempt record
                    attempt_record = RuleAttempt(
                        finding_id=finding_id,
                        attempt_no=attempt_no,
                        strategy=strategy,
                        proposal_json=proposal_json_str,
                        rule_text=rule_text,
                        syntax_ok=bool(syntax_ok),
                        attacks_blocked=exam.get("attacks_blocked", 0),
                        attacks_total=exam.get("attacks_total", 0),
                        users_ok=exam.get("users_ok", 0),
                        users_total=exam.get("users_total", 0),
                        passed=exam.get("passed", False),
                        failure_reason=json.dumps(exam.get("failures", [])) if not exam.get("passed", False) else None,
                        created_at=get_utc_now()
                    )
                    with Session(api.db.engine) as s:
                        s.add(attempt_record)
                        s.commit()

            finding_dict = {
                "id": finding.id,
                "target": finding.target,
                "parameter": finding.parameter,
                "type": finding.type,
                "description": finding.description
            }

            result = run_practice(finding_dict, on_step_callback, settings.sandbox_shield_url)
            
            # Check generation again before finalizing
            if PROTECT_GENERATION.get(finding_id) != my_gen:
                return

            f = session.get(Finding, finding_id)
            if f:
                if result.get("status") == "TESTED" or (result.get("exam", {}).get("passed") is True):
                    f.status = FindingStatus.TESTED
                    ACTIVE_PIPELINE_STEPS[finding_id] = "approve"
                else:
                    f.status = FindingStatus.FAILED
                    ACTIVE_PIPELINE_STEPS[finding_id] = "failed"
                session.add(f)
                session.commit()
                logger.info("Practice task complete for %s. New status: %s", finding_id, f.status)

    except Exception as e:
        logger.error("Unhandled error in practice task for %s: %s", finding_id, e)
        with Session(api.db.engine) as session:
            f = session.get(Finding, finding_id)
            if f and f.status == FindingStatus.PROTECTING:
                f.status = FindingStatus.FAILED
                ACTIVE_PIPELINE_STEPS[finding_id] = "failed"
                session.add(f)
                session.commit()
    finally:
        ACTIVE_PROTECT_RUNS.discard(finding_id)

@app.post("/protect/{id}", status_code=status.HTTP_202_ACCEPTED, summary="Start Practice Room testing")
def start_protection(id: str, background_tasks: BackgroundTasks, session: Session = Depends(get_session)):
    finding = session.get(Finding, id)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding '{id}' not found.")

    if id in ACTIVE_PROTECT_RUNS:
        return {"status": "in_progress", "message": f"Practice Room is already running for {id}."}

    # Generation counter ensures a new protection run invalidates any lingering callbacks
    PROTECT_GENERATION[id] = PROTECT_GENERATION.get(id, 0) + 1
    ACTIVE_PIPELINE_STEPS[id] = "analyze"

    # Clear evidence from any previous run so a clean attempt list is established
    for old in session.exec(select(RuleAttempt).where(RuleAttempt.finding_id == id)).all():
        session.delete(old)
    session.commit()

    # Mark PROTECTING
    finding.status = FindingStatus.PROTECTING
    session.add(finding)
    session.commit()

    ACTIVE_PROTECT_RUNS.add(id)
    background_tasks.add_task(_background_practice_task, id)

    return {
        "status": "started",
        "message": f"Practice Room workflow started for finding {id}.",
        "finding_id": id
    }

@app.get("/status/{id}", response_model=FindingStatusResponse, summary="Poll workflow status and attempts")
def get_finding_status(id: str, session: Session = Depends(get_session)):
    finding = session.get(Finding, id)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding '{id}' not found.")

    statement = (
        select(RuleAttempt)
        .where(RuleAttempt.finding_id == id)
        .order_by(RuleAttempt.attempt_no.asc())
    )
    attempts = session.exec(statement).all()

    # Determine current pipeline step
    if finding.status == FindingStatus.NEW:
        current_step = "Analyze"
    elif finding.status == FindingStatus.PROTECTING:
        active_step = ACTIVE_PIPELINE_STEPS.get(id)
        if active_step:
            current_step = active_step.capitalize()
        else:
            current_step = "Exam" if attempts else "Generate"
    elif finding.status == FindingStatus.TESTED:
        current_step = "Approve"
    elif finding.status in (FindingStatus.LIVE, FindingStatus.FIX_VERIFIED, FindingStatus.RETIRED):
        current_step = "Live"
    elif finding.status == FindingStatus.FAILED:
        current_step = "Failed"
    else:
        current_step = "Analyze"

    attempt_responses: List[RuleAttemptResponse] = []
    passing_attempt: Optional[RuleAttemptResponse] = None

    for a in attempts:
        prop = json.loads(a.proposal_json) if a.proposal_json else None
        res = RuleAttemptResponse(
            id=a.id,
            finding_id=a.finding_id,
            attempt_no=a.attempt_no,
            strategy=a.strategy,
            proposal=prop,
            rule_text=a.rule_text,
            syntax_ok=a.syntax_ok,
            attacks_blocked=a.attacks_blocked,
            attacks_total=a.attacks_total,
            users_ok=a.users_ok,
            users_total=a.users_total,
            passed=a.passed,
            failure_reason=a.failure_reason,
            created_at=a.created_at
        )
        attempt_responses.append(res)
        if a.passed:
            passing_attempt = res

    mttp_str, mttp_sec = calculate_mttp(finding, session)
    f_res = FindingResponse(
        id=finding.id,
        target=finding.target,
        parameter=finding.parameter,
        type=finding.type,
        severity=finding.severity,
        source=finding.source,
        description=finding.description,
        status=finding.status,
        created_at=finding.created_at,
        mttp=mttp_str,
        mttp_seconds=mttp_sec
    )

    return FindingStatusResponse(
        finding=f_res,
        current_step=current_step,
        step=current_step.lower(),
        status=finding.status,
        attempts=attempt_responses,
        passing_attempt=passing_attempt
    )

# ------------------------------------------------------------------------------
# 4. Lifecycle Actions (Approve, Rollback, Verify-Fix)
# ------------------------------------------------------------------------------
@app.post("/approve/{id}", response_model=ActionResponse, summary="Human approval to deploy rule to LIVE shield")
def approve_rule(id: str, body: ApproveRequest = ApproveRequest(), session: Session = Depends(get_session)):
    try:
        result = approve_finding(id, body.approved_by, session)
        return ActionResponse(
            status="success",
            message=result["message"],
            finding_id=id,
            current_status=result["current_status"],
            details=result
        )
    except LifecycleError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error("Approve error on %s: %s", id, e)
        raise HTTPException(status_code=500, detail=f"Deployment error: {e}")

@app.post("/rollback/{id}", response_model=ActionResponse, summary="Roll back rule from LIVE shield")
def rollback_rule(id: str, session: Session = Depends(get_session)):
    try:
        result = rollback_finding(id, session)
        return ActionResponse(
            status="success",
            message=result["message"],
            finding_id=id,
            current_status=result["current_status"],
            details=result
        )
    except LifecycleError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error("Rollback error on %s: %s", id, e)
        raise HTTPException(status_code=500, detail=f"Rollback error: {e}")

def _set_victim_mode(mode: str) -> bool:
    """
    Sends mode update ('fixed' or 'vulnerable') to victim-sandbox.
    Tries sandbox shield proxy, direct victim-sandbox:5000, and local fallback URLs.
    """
    candidate_urls = [
        f"{settings.sandbox_shield_url.rstrip('/')}/api/mode",
        "http://localhost:5000/api/mode",
        "http://victim-sandbox:5000/api/mode",
        "http://127.0.0.1:5000/api/mode",
    ]
    for url in candidate_urls:
        try:
            resp = requests.post(url, json={"mode": mode}, timeout=0.5)
            if resp.status_code == 200:
                logger.info("Successfully updated victim-sandbox mode to '%s' via %s", mode, url)
                return True
        except Exception:
            continue
    logger.warning("Could not reach victim-sandbox to set mode to '%s' (may be offline in mock tests)", mode)
    return False

@app.post("/verify-fix/{id}", response_model=ActionResponse, summary="Feature 3: Verify permanent fix and retire temporary rule")
def verify_fix(id: str, session: Session = Depends(get_session)):
    # 1. Before running naked app exam against victim-sandbox, issue POST with {"mode": "fixed"}
    _set_victim_mode("fixed")
    try:
        result = verify_fix_and_retire(id, session)
        # If exam fails or incomplete, auto-revert payload {"mode": "vulnerable"}
        if result.get("status") != "success" or not result.get("retired"):
            _set_victim_mode("vulnerable")

        return ActionResponse(
            status=result["status"],
            message=result["message"],
            finding_id=id,
            current_status=result["current_status"],
            details=result
        )
    except LifecycleError as e:
        _set_victim_mode("vulnerable")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        _set_victim_mode("vulnerable")
        logger.error("Verify-fix error on %s: %s", id, e)
        raise HTTPException(status_code=500, detail=f"Verification error: {e}")

@app.get("/fix/{id}", summary="Permanent fix guidance (before/after code)")
def get_fix_guidance(id: str, session: Session = Depends(get_session)):
    finding = session.get(Finding, id)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding '{id}' not found.")
    
    finding_dict = {
        "id": finding.id,
        "target": finding.target,
        "parameter": finding.parameter,
        "type": finding.type
    }
    return suggest_fix(finding_dict)

# ------------------------------------------------------------------------------
# 4b. FixFort Sentinel (Agent37 Hermes Cloud Security Review)
# ------------------------------------------------------------------------------
@app.post("/sentinel/review/{id}", response_model=SentinelReviewResponse, summary="Agent-assisted security review via Agent37 Cloud")
def trigger_sentinel_review(id: str, session: Session = Depends(get_session)):
    finding = session.get(Finding, id)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding '{id}' not found.")

    # Fetch attempts to find the latest or passing rule attempt
    attempts = session.exec(
        select(RuleAttempt).where(RuleAttempt.finding_id == id).order_by(RuleAttempt.attempt_no.desc())
    ).all()

    rule_attempt_dict = None
    exam_dict = None

    if attempts:
        # Prefer a passing attempt if one exists, otherwise the latest attempt
        selected_attempt = next((a for a in attempts if a.passed), attempts[0])
        prop = json.loads(selected_attempt.proposal_json) if selected_attempt.proposal_json else {}
        rule_attempt_dict = {
            "attempt_no": selected_attempt.attempt_no,
            "strategy": selected_attempt.strategy,
            "rule_text": selected_attempt.rule_text,
            "syntax_ok": selected_attempt.syntax_ok,
            "proposal": prop,
            "reason": prop.get("reason", f"Rule attempt {selected_attempt.attempt_no}")
        }
        failures_list = []
        if selected_attempt.failure_reason:
            try:
                failures_list = json.loads(selected_attempt.failure_reason)
            except Exception:
                failures_list = [selected_attempt.failure_reason]

        exam_dict = {
            "attacks_blocked": selected_attempt.attacks_blocked,
            "attacks_total": selected_attempt.attacks_total,
            "users_ok": selected_attempt.users_ok,
            "users_total": selected_attempt.users_total,
            "passed": selected_attempt.passed,
            "failures": failures_list
        }

    finding_dict = {
        "id": finding.id,
        "target": finding.target,
        "parameter": finding.parameter,
        "type": finding.type,
        "severity": finding.severity,
        "description": finding.description
    }

    review = review_with_agent37(finding_dict, rule_attempt_dict, exam_dict)
    SENTINEL_REVIEWS[id] = review

    return SentinelReviewResponse(**review)


@app.get("/sentinel/review/{id}", response_model=SentinelReviewResponse, summary="Get latest Sentinel review")
def get_sentinel_review(id: str, session: Session = Depends(get_session)):
    if id in SENTINEL_REVIEWS:
        return SentinelReviewResponse(**SENTINEL_REVIEWS[id])
    return trigger_sentinel_review(id, session)

# ------------------------------------------------------------------------------
# 5. Live Events Feed
# ------------------------------------------------------------------------------
@app.get("/events", response_model=List[EventResponse], summary="Poll live threat feed")
def get_events(
    since: Optional[str] = Query(None, description="Cursor: integer event ID or ISO timestamp"),
    limit: int = Query(50, ge=1, le=200),
    session: Session = Depends(get_session)
):
    # Ensure fresh log lines are read before querying
    event_reader.process_new_events()

    statement = select(Event)
    if since:
        # Check if since is integer ID or timestamp
        if since.isdigit():
            statement = statement.where(Event.id > int(since))
        else:
            try:
                dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
                statement = statement.where(Event.ts > dt)
            except ValueError:
                pass # invalid format, ignore filter

    statement = statement.order_by(Event.id.desc()).limit(limit)
    events = session.exec(statement).all()
    
    # Return chronologically ascending for the frontend
    return [
        EventResponse(
            id=e.id,
            ts=e.ts,
            method=e.method,
            path=e.path,
            query=e.query,
            status_code=e.status_code,
            outcome=e.outcome,
            rule_id=e.rule_id
        )
        for e in reversed(events)
    ]

# ------------------------------------------------------------------------------
# 6. Protection Certificate
# ------------------------------------------------------------------------------
@app.get("/certificate/{id}", response_model=CertificateResponse, summary="Get audit evidence for Protection Certificate")
def get_certificate(id: str, session: Session = Depends(get_session)):
    finding = session.get(Finding, id)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding '{id}' not found.")

    statement = (
        select(Deployment)
        .where(Deployment.finding_id == id)
        .order_by(Deployment.approved_at.desc())
    )
    deployment = session.exec(statement).first()

    rule_text = None
    approver = None
    approved_at = None
    fix_verified_at = None
    retired_at = None
    rule_id_str = None
    exam_attacks = "N/A"
    exam_users = "N/A"

    if deployment:
        approver = deployment.approved_by
        approved_at = deployment.approved_at
        fix_verified_at = deployment.fix_verified_at
        retired_at = deployment.retired_at
        rule_id_str = f"FF-{finding.id}"

        passing_attempt = session.get(RuleAttempt, deployment.attempt_id)
        if passing_attempt:
            rule_text = passing_attempt.rule_text
            exam_attacks = f"{passing_attempt.attacks_blocked}/{passing_attempt.attacks_total}"
            exam_users = f"{passing_attempt.users_ok}/{passing_attempt.users_total}"

    mttp_display, mttp_seconds = calculate_mttp(finding, session)

    return CertificateResponse(
        finding_id=finding.id,
        finding_type=finding.type,
        target=finding.target,
        parameter=finding.parameter,
        severity=finding.severity,
        status=finding.status,
        rule_id=rule_id_str,
        approved_rule_text=rule_text,
        approved_by=approver,
        created_at=finding.created_at,
        approved_at=approved_at,
        fix_verified_at=fix_verified_at,
        retired_at=retired_at,
        mttp_seconds=mttp_seconds,
        mttp_display=mttp_display or "Ongoing",
        exam_attacks=exam_attacks,
        exam_users=exam_users,
        is_verified_and_retired=(finding.status == FindingStatus.RETIRED)
    )

# ------------------------------------------------------------------------------
# 7. Demo Helper Endpoint (Controlled Demonstration Only)
# ------------------------------------------------------------------------------
ALLOWED_ATTACKS = {
    "sqli_tautology": {
        "method": "POST",
        "path": "/login",
        "data": {"username": "' OR 1=1 --", "password": "x"}
    },
    "sqli_admin_comment": {
        "method": "POST",
        "path": "/login",
        "data": {"username": "admin'--", "password": "x"}
    },
    "sqli_union": {
        "method": "POST",
        "path": "/login",
        "data": {"username": "' UNION SELECT 1,'admin','x' --", "password": "x"}
    },
    "xss_script": {
        "method": "POST",
        "path": "/comment",
        "data": {"text": "<script>alert(1)</script>"}
    },
    "login_obrien": {
        "method": "POST",
        "path": "/login",
        "data": {"username": "O'Brien", "password": "obrienpass"}
    },
    "comment_obrien": {
        "method": "POST",
        "path": "/comment",
        "data": {"text": "Dr. O'Brien was kind"}
    },
    "comment_valid_bracket": {
        "method": "POST",
        "path": "/comment",
        "data": {"text": "5 < 6, loved it"}
    },
    "php2shell_exploit": {
        "method": "POST",
        "path": "/upload.php",
        "data": {"note": "<?php system($_GET['c']); ?>"}
    },
    "php_upload_valid": {
        "method": "POST",
        "path": "/upload.php",
        "data": {"note": "O'Brien's scan results"}
    }
}

_SCAN_PROBES = [
    {"id": "F-001", "target": "/login", "type": "sqli", "severity": "high",
     "data": {"username": "' OR 1=1 --", "password": "x"}, "marker": "welcome"},
    {"id": "F-002", "target": "/comment", "type": "xss", "severity": "medium",
     "data": {"text": "<script>fixfort-probe</script>"}, "marker": "<script>fixfort-probe"},
    {"id": "F-004", "target": "/upload.php", "type": "php_rce", "severity": "critical",
     "data": {"note": "<?php /*fixfort-probe*/ system($_GET[c]); ?>"}, "marker": "rce-simulated"},
]

@app.post("/scan", summary="Built-in scanner: probe the demo site and report confirmed vulnerabilities")
def scan_target():
    base = settings.demo_target_url.rstrip("/")
    log = []
    for p in _SCAN_PROBES:
        try:
            r = requests.post(base + p["target"], data=p["data"], timeout=3.0)
            vulnerable = p["marker"] in (r.text or "").lower()
        except Exception:
            vulnerable = False
        log.append({"id": p["id"], "target": p["target"], "type": p["type"],
                    "severity": p["severity"], "vulnerable": vulnerable})
    discovered = [p["id"] for p, e in zip(_SCAN_PROBES, log) if e["vulnerable"]]
    return {"scanned": len(_SCAN_PROBES), "discovered": discovered, "log": log}

@app.post("/attack/{name}", response_model=AttackHelperResponse, summary="Demo helper: replay allowlisted attack or good user request")
def send_demo_attack(name: str):
    if name not in ALLOWED_ATTACKS:
        raise HTTPException(
            status_code=400,
            detail=f"Attack '{name}' is not in the allowlist. Allowed: {list(ALLOWED_ATTACKS.keys())}"
        )

    action = ALLOWED_ATTACKS[name]
    target_url = f"{settings.demo_target_url.rstrip('/')}{action['path']}"
    method = action["method"]
    payload = action["data"]

    try:
        if method == "POST":
            resp = requests.post(target_url, data=payload, timeout=3.0)
        else:
            resp = requests.get(target_url, params=payload, timeout=3.0)

        status_code = resp.status_code
        text_preview = resp.text[:150]
    except Exception as e:
        status_code = 502
        text_preview = f"Target unreachable at {target_url} ({e})"

    blocked = (status_code == 403)
    outcome = "blocked" if blocked else "allowed"

    return AttackHelperResponse(
        attack_name=name,
        target_url=target_url,
        method=method,
        payload=payload,
        response_status=status_code,
        blocked=blocked,
        outcome=outcome,
        response_preview=text_preview
    )

# ------------------------------------------------------------------------------
# 7b. Demo Mode Control (vulnerable vs fixed clinic mode)
# ------------------------------------------------------------------------------
class DemoModePayload(BaseModel):
    mode: str

@app.get("/demo/mode", summary="Get demo clinic vulnerability mode")
def get_demo_mode():
    for u in ["http://localhost:8080/api/mode", "http://localhost:5000/api/mode", f"{settings.sandbox_shield_url.rstrip('/')}/api/mode"]:
        try:
            r = requests.get(u, timeout=0.25)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
    return {"mode": "vulnerable"}

@app.post("/demo/mode", summary="Set demo clinic vulnerability mode (vulnerable or fixed)")
def set_demo_mode(req: DemoModePayload):
    if req.mode not in ("vulnerable", "fixed"):
        raise HTTPException(status_code=400, detail="mode must be vulnerable or fixed")
    for u in ["http://localhost:8080/api/mode", "http://localhost:5000/api/mode", f"{settings.sandbox_shield_url.rstrip('/')}/api/mode", f"{settings.live_shield_url.rstrip('/')}/api/mode"]:
        try:
            requests.post(u, json={"mode": req.mode}, timeout=0.5)
        except Exception:
            pass
    return {"mode": req.mode, "status": "updated"}

# ------------------------------------------------------------------------------
# 8. Reset Mechanism
# ------------------------------------------------------------------------------
@app.post("/reset", summary="Reset demo state: clears rule files and database to initial seed")
def reset_system():
    # Restricted to development and demonstration modes
    if settings.environment not in ("demonstration", "development", "test"):
        raise HTTPException(status_code=403, detail="Reset is disabled in production environment.")

    try:
        # Clear in-memory active tasks, steps, and generation counters
        ACTIVE_PROTECT_RUNS.clear()
        ACTIVE_PIPELINE_STEPS.clear()
        PROTECT_GENERATION.clear()
        SENTINEL_REVIEWS.clear()
        # Clear rules
        clear_all_rules()
        # Reset DB
        reset_db()
        # Seed fresh findings
        seed_sample_findings()
        # Restore both clinic apps to vulnerable mode so a repeat demo starts clean
        # (a prior verify-fix may have left the sandbox in 'fixed' mode).
        for url in (settings.sandbox_shield_url, settings.live_shield_url, "http://localhost:8080", "http://localhost:5000"):
            try:
                requests.post(url.rstrip("/") + "/api/mode", json={"mode": "vulnerable"}, timeout=1)
            except Exception as _e:
                pass
        logger.info("System successfully reset to clean state.")
        return {
            "status": "reset",
            "message": "Demo state reset successfully. Database and rule folders cleared."
        }
    except Exception as e:
        logger.error("Failed during system reset: %s", e)
        raise HTTPException(status_code=500, detail=f"Reset failure: {e}")
