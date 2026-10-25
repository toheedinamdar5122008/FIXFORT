# FixFort — The Fort Between Vulnerability and Resolution

> **Hackyard Build 2026 | IIT Guwahati (24–25 October)**  
> **Person B Implementation: Platform & Data Engineer ("The Backbone")**

---

## 1. Project Overview & Philosophy

FixFort provides temporary protection and verified retirement for vulnerable web applications and connected devices before a permanent code fix is shipped.

Think of a burst pipe in your house: you shut the valve or clamp the pipe immediately while the plumber prepares the proper repair. FixFort installs a temporary security rule, validates it in an isolated sandbox ("The Practice Room"), requires human approval before deployment, and removes it only after the permanent code fix is proven safe.

**The Golden Motto:**  
> *"The AI suggests, the Practice Room proves, the human decides, and nothing stays temporary forever."*

---

## 2. Person B Implementation Scope

As Person B ("The Backbone"), this repository provides:
1. **Container Infrastructure (`docker-compose.yml`)**:
   - `victim-live`: Demonstration clinic portal (internal network only; never exposed to host).
   - `victim-sandbox`: Isolated testing copy for the Practice Room (internal network only).
   - `shield-live`: Nginx + ModSecurity WAF reverse proxying `victim-live` (Port `8080`).
   - `shield-sandbox`: Nginx + ModSecurity WAF reverse proxying `victim-sandbox` (Port `8081`).
   - `api`: FastAPI backend orchestrating the platform (Port `8000`).
2. **Shield Control Engine (`api/shield_ctl.py`)**:
   - Atomic file operations (`apply_rule`, `remove_rule`).
   - Pre-live candidate syntax validation (`check_syntax`).
   - Graceful reload without container restarts (`reload`).
   - Strict input validation against path traversal and shell injection.
3. **Database Architecture (`api/models.py`, `api/db.py`)**:
   - SQLite persistent storage via SQLModel.
   - Tables: `findings`, `rule_attempts`, `deployments`, `events`.
   - Audit trail storing every AI attempt (including the "O'Brien catch"), lifecycle timestamps, and Mean Time to Protection (MTTP).
4. **FastAPI Backend (`api/main.py`)**:
   - REST API serving Person C's React Dashboard with 1-second polling support.
   - Background task orchestration for the Practice Room.
   - Enforced safety checks: only tested, passing rules can be approved.
   - Safe one-click rollback (`POST /rollback/{id}`).
   - Complete **Verify-Fix-and-Retire** lifecycle (`POST /verify-fix/{id}`).
5. **Real-time Live Event Feed (`api/events.py`)**:
   - Structured JSON access log parser from the live shield (`shield/logs/access.log`).
   - Automatic query parameter sanitization (redacts passwords and tokens).
6. **Deterministic Integration Boundaries (`api/brain_adapter.py`)**:
   - Clean interface to Person A's AI rule generator and exam runner.
   - Fallback adapter for isolated development and offline laptop testing.

---

## 3. Technology Stack

- **Language & Runtime**: Python 3.11+ / 3.14 compatible.
- **API Framework**: FastAPI with Pydantic v2 and Uvicorn.
- **Database & ORM**: SQLite with SQLModel (SQLAlchemy 2.0 core).
- **Reverse Proxy & WAF**: Nginx + OWASP ModSecurity engine.
- **Container Orchestration**: Docker & Docker Compose.
- **Testing**: pytest with HTTPX test client.

---

## 4. Quickstart: Running Locally

### Step 1: Install Dependencies
```powershell
python -m pip install -r requirements.txt
```

### Step 2: Configure Environment
Copy `.env.example` to `.env` (defaults work out-of-the-box):
```powershell
Copy-Item .env.example .env
```

### Step 3: Run Automated Tests
Execute the comprehensive test suite (23 unit, lifecycle, and integration tests):
```powershell
python -m pytest -v
```

### Step 4: Start the FastAPI Backend
```powershell
python -m uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```
Interactive OpenAPI documentation is immediately accessible at:
- **Swagger UI**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **ReDoc**: [http://localhost:8000/redoc](http://localhost:8000/redoc)

---

## 5. Running with Docker Compose

When Docker Desktop is running on the host machine:

```bash
# Build and start all 5 services
docker compose up --build -d

# Check service status and healthchecks
docker compose ps

# View live shield access logs
docker compose logs -f shield-live

# Graceful stop
docker compose down
```

### Port Mapping:
- Live Shield (Protects Victim Live): `http://localhost:8080`
- Sandbox Shield (The Practice Room): `http://localhost:8081`
- FixFort Backend API: `http://localhost:8000`
- Victim apps: **Internal only** (no host ports exposed).

---

## 6. Complete End-to-End Demonstration Workflow

### Step 1: Initial State & Finding Import
1. Ensure the demo is reset:
   ```bash
   curl -X POST http://localhost:8000/reset
   ```
2. Verify finding `F-001` (SQL Injection on `/login`):
   ```bash
   curl http://localhost:8000/findings
   ```

### Step 2: The Practice Room (The O'Brien Catch)
1. Start the automated protection loop:
   ```bash
   curl -X POST http://localhost:8000/protect/F-001
   ```
2. Poll the status until `TESTED`:
   ```bash
   curl http://localhost:8000/status/F-001
   ```
   **What happens under the hood:**
   - **Attempt 1 (Strict strategy)**: Blocks single quote `'`. Stops the SQLi attack, but good-user test *"login as O'Brien"* fails with 403!
   - **Attempt 2 (Precise strategy)**: Receives failure feedback, narrows pattern to `(?i)'\s*(or|and)\s+['\d]|--|;|union\s+select`.
   - **Result**: 5/5 attacks blocked, 20/20 legitimate users pass! Finding transitions to `TESTED`.

### Step 3: Human Approval & Deployment
1. Approve the tested rule:
   ```bash
   curl -X POST http://localhost:8000/approve/F-001 -H "Content-Type: application/json" -d "{\"approved_by\": \"Security Lead\"}"
   ```
   - Pre-validates rule syntax.
   - Deploys rule file to `shield/rules-live/fixfort-F-001.conf`.
   - Reloads live shield.
   - Stores `approved_at` timestamp and transitions status to `LIVE`.

### Step 4: Replay Attacks & Threat Feed
1. Send an attack through the live shield helper:
   ```bash
   curl -X POST http://localhost:8000/attack/sqli_tautology
   # Response: {"blocked": true, "response_status": 403, "outcome": "blocked"}
   ```
2. Send legitimate user request:
   ```bash
   curl -X POST http://localhost:8000/attack/login_obrien
   # Response: {"blocked": false, "response_status": 200, "outcome": "allowed"}
   ```
3. Poll live events:
   ```bash
   curl "http://localhost:8000/events?limit=10"
   ```

### Step 5: Verify-Fix-and-Retire (Feature 3)
1. **Case A: Fix Incomplete (Demonstration)**:
   - If the developer claims the bug is fixed, but the attack still succeeds:
   ```bash
   curl -X POST http://localhost:8000/verify-fix/F-001
   # Live protection remains active! Rule is NOT retired.
   ```
2. **Case B: Code Fix Verified & Proven**:
   - Once both victim applications are switched to fixed mode (parameterized queries):
   - The Practice Room re-runs exams against the naked application without the temporary rule.
   - All attacks fail because the code is secure.
   - The temporary rule is safely removed from the live shield.
   - Status transitions to `RETIRED` with `fix_verified_at` and `retired_at` recorded!
   ```bash
   # Response: {"status": "success", "message": "Code fix confirmed. Temporary rule retired."}
   ```

### Step 6: Protection Certificate
Retrieve the complete evidence record for Person C's printable Certificate:
```bash
curl http://localhost:8000/certificate/F-001
```

---

## 7. Security Safeguards

1. **Strict Path Isolation**: Rule IDs and filenames are sanitized using strict alphanumeric constraints (`^[a-zA-Z0-9_\-]+$`) with path traversal guards.
2. **Pre-Live Validation**: Rules must pass syntax validation before being committed to the live shield.
3. **Subprocess Hardening**: Controlled argument lists with execution timeouts; no shell interpolation.
4. **Data Minimization & Log Sanitization**: Passwords, tokens, and authorization parameters are automatically masked in the event feed.
5. **Fail-Closed Verification**: The live rule is never retired unless sandbox exam proves 100% attack blocking and 100% legitimate user pass rates on the naked codebase.

---

## 8. Troubleshooting Guide

| Issue | Cause | Fix |
| :--- | :--- | :--- |
| `Docker command not found` | Docker Desktop is not installed or not in PATH | The backend automatically detects this and falls back to local syntax and rule management mode (`SHIELD_EXEC_MODE=local`). |
| `Port 8000 or 8080 in use` | Another service is using the port | Update `API_PORT` or `LIVE_SHIELD_URL` in `.env`. |
| `Cannot approve finding` | Finding is not in `TESTED` state or exam failed | Run `POST /protect/{id}` first and verify attempts passed. |
| `CORS error in Dashboard` | Dashboard origin not allowlisted | Ensure `http://localhost:5173` is in `CORS_ORIGINS` in `.env`. |
