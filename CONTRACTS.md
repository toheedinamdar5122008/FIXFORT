# FixFort Shared Contracts (CONTRACTS.md)
*Source of Truth for Team FixFort (Hackyard Build 2026)*

> **Core Philosophy**: *"The AI suggests, the Practice Room proves, the human decides, and nothing stays temporary forever."*

---

## 1. Finding Schema (Input to FixFort)

```json
{
  "id": "F-001",
  "target": "/login",
  "parameter": "username",
  "type": "sqli",
  "severity": "high",
  "source": "zap",
  "description": "Login query built by string concatenation"
}
```

### Fields:
- `id` (*string*, required): Unique identifier, e.g. `"F-001"`.
- `target` (*string*, required): Target HTTP path, e.g. `"/login"`.
- `parameter` (*string*, required): Vulnerable parameter name, e.g. `"username"`.
- `type` (*string*, required): Vulnerability category (`"sqli"`, `"xss"`, `"param"`).
- `severity` (*string*, optional): `"critical"`, `"high"`, `"medium"`, `"low"`.
- `source` (*string*, optional): Finding origin, e.g. `"zap"`, `"manual"`.
- `description` (*string*, optional): Human-readable summary.

---

## 2. Rule Proposal Schema (Person A LLM Output)

```json
{
  "target": "/login",
  "parameter": "username",
  "strategy": "strict | precise",
  "pattern": "(?i)('\\s*or\\s+['\\d])|(--)|(;)|(union\\s+select)",
  "reason": "Blocks boolean tautology, comment syntax, and union injection while permitting apostrophes in names."
}
```

---

## 3. Exam Result Schema (The Practice Room Report)

```json
{
  "attacks_blocked": 5,
  "attacks_total": 5,
  "users_ok": 20,
  "users_total": 20,
  "passed": true,
  "failures": [
    { "kind": "user", "name": "login as O'Brien", "got": 403 }
  ]
}
```

### Passing Condition:
`passed == (attacks_blocked == attacks_total) and (users_ok == users_total)`

---

## 4. Finding Status Lifecycle & State Transitions

```
NEW ──▶ PROTECTING ──▶ TESTED ──▶ LIVE ──▶ RETIRED
  │                       │         │
  └──────▶ FAILED ◀───────┘         └──▶ ROLLED_BACK
```

| From | To | Condition / Trigger |
| :--- | :--- | :--- |
| `NEW` | `PROTECTING` | `POST /protect/{id}` initiated. |
| `PROTECTING` | `TESTED` | Practice Room completes and exam reports `passed == true`. |
| `PROTECTING` | `FAILED` | Maximum retries and fallback templates exhausted without passing. |
| `TESTED` | `LIVE` | Explicit human action via `POST /approve/{id}`. Rule syntax re-checked and deployed. |
| `LIVE` | `ROLLED_BACK` | Explicit human action via `POST /rollback/{id}`. Rule removed from live shield. |
| `LIVE` | `RETIRED` | Permanent fix verified on naked app code (`POST /verify-fix/{id}`) and rule retired from live shield. |

---

## 5. MTTP (Mean Time to Protection) Convention

- **Definition**: Time elapsed between vulnerability detection and active live shield protection.
- **Formula**: `MTTP = approved_at - created_at`
- **Units**: Calculated in integer seconds, formatted for display as:
  * `< 60s`: `"45s"`
  * `< 3600s`: `"2m 15s"`
  * `≥ 3600s`: `"1h 10m"`
- If a finding is not yet deployed to live, MTTP is marked `"Ongoing"` or `null`.

---

## 6. Python Function Contracts (Person A ⟷ Person B)

| Function | Owner | Signature | Description |
| :--- | :---: | :--- | :--- |
| `propose_rule` | A | `propose_rule(finding, feedback=None, strategy="strict") -> dict` | Generates JSON rule proposal. |
| `to_modsec` | A | `to_modsec(proposal, rule_id) -> str` | Converts JSON proposal to chained ModSecurity `SecRule`. |
| `run_exam` | A | `run_exam(base_url, finding) -> dict` | Executes 5 attack payloads + 20 good-user requests against target URL. |
| `run_practice` | A | `run_practice(finding, on_step) -> dict` | Orchestrates propose $\to$ syntax $\to$ exam $\to$ retry. Invokes `on_step(name, data)`. |
| `suggest_fix` | A | `suggest_fix(finding) -> {"before": str, "after": str, "explanation": str}` | Permanent code remediation advice. |
| `apply_rule` | B | `apply_rule(env, rule_id, text) -> bool` | Atomically writes rule file in `rules-<env>/`. |
| `remove_rule` | B | `remove_rule(env, rule_id) -> bool` | Deletes specific rule file in `rules-<env>/`. |
| `check_syntax` | B | `check_syntax(env) -> (bool, str)` | Runs `nginx -t` validation inside shield container. |
| `reload` | B | `reload(env) -> (bool, str)` | Runs graceful `nginx -s reload` inside shield container. |

*Rule Directories*: `env` must be strictly `"sandbox"` or `"live"`.

---

## 7. REST API Endpoints (Person B ⟷ Person C)

| Method | Endpoint | Description | Used By Dashboard Screen |
| :--- | :--- | :--- | :--- |
| `GET` | `/health` | Basic service health probe | Navigation Top Bar |
| `GET` | `/ready` | Deep infrastructure health check | Top Bar Status Pills |
| `GET` | `/findings` | List all findings with status and MTTP | Screen 1: Command Center |
| `POST` | `/findings` | Import finding (JSON or ZAP export) | Screen 1: Command Center |
| `POST` | `/protect/{id}` | Start Practice Room loop in background | Screen 1 & 2: Pipeline |
| `GET` | `/status/{id}` | Poll pipeline step, rule attempts, exam numbers | Screen 2: Pipeline (polled 1s) |
| `POST` | `/approve/{id}` | Approve passing rule and deploy to live shield | Screen 2: Pipeline |
| `POST` | `/rollback/{id}` | Roll back rule from live shield | Screen 2 & 4: Lifecycle |
| `POST` | `/verify-fix/{id}` | Feature 3: Verify permanent fix & retire temporary rule | Screen 4: Lifecycle |
| `GET` | `/fix/{id}` | Before/after remediation code diff | Screen 4: Lifecycle |
| `GET` | `/events?since=...` | Live threat feed of allowed/blocked requests | Screen 3: Threat Feed (polled 1s) |
| `GET` | `/certificate/{id}` | Complete audit trail for Protection Certificate | Screen 4: Certificate |
| `POST` | `/attack/{name}` | Attacker console demo helper | Screen 3: Threat Feed |
| `POST` | `/reset` | Re-seed initial demo state | Pre-demo reset |

---

## 8. Event Feed Semantics (`GET /events?since=...`)

- **Cursor**: `since` accepts either an integer event ID (e.g. `?since=42`) or an ISO-8601 timestamp (`?since=2026-10-16T15:00:00Z`).
- **Ordering**: Ascending chronological order so the frontend can append rows seamlessly.
- **Fields**: `id`, `ts`, `method`, `path`, `query`, `status_code`, `outcome` (`"allowed"` or `"blocked"`), `rule_id`.
- **Sanitization**: Password and authentication token parameters are automatically redacted from logged queries.

---

## 9. Standard Error Response Format

```json
{
  "detail": "Descriptive, actionable error explanation."
}
```
Standard HTTP status codes:
- `400 Bad Request`: Lifecycle rule violation, invalid payload, or unknown demo attack.
- `404 Not Found`: Finding does not exist.
- `422 Unprocessable Entity`: Validation failure on required fields.
- `500 Internal Server Error`: Infrastructure or command failure with recovery context.
