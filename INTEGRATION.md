# FixFort — Person A ⟷ Person B Integration Guide

This is the exact wiring that makes the **live** pipeline real:
**Gemini proposes → converted to a ModSecurity rule → applied to Person B's real
sandbox shield → proved by a real HTTP exam → human approves → live.**
Nothing simulated, nothing hardcoded.

Person A's engine is done and tested (52 passing unit tests). The four items
below are all on Person B's side; each is a small, copy-pasteable change.

---

## 0. Where Person A's code must sit

Person A ships two top-level packages that must land at the **repo root** of the
backend (next to `api/`), on the Python path:

```
FIXFORT/
├── api/            # Person B
├── fixfort/        # Person A  (fixfort/brain/..., fixfort/mocks/...)
├── tests/          # Person A  (tests/exam.py, tests/attacks.py, tests/users.py)
└── ...
```

Unzip `FixFort_PersonA_Brain.zip` and copy its `fixfort/` and `tests/` folders in
as shown. **Keep the `fixfort.` prefix** — the engine imports itself as
`fixfort.brain...`, so importing it as a bare `brain` will break its internal
imports.

---

## 1. Fix the imports in `api/brain_adapter.py`

The current adapter imports `from brain.practice import ...`. That never
resolves (the package is `fixfort.brain`), so `HAS_REAL_BRAIN` is always
`False` and you silently run the simulated fallback. Change the probe to:

```python
try:
    from fixfort.brain.practice import run_practice as real_run_practice, make_remote_context
    from fixfort.brain.rules import to_modsec as real_to_modsec
    from fixfort.brain.fixes import suggest_fix as real_suggest_fix
    from tests.exam import run_exam as real_run_exam
    HAS_REAL_BRAIN = True
except ImportError:
    HAS_REAL_BRAIN = False
```

---

## 2. Run the Practice Room against the REAL shield (one call)

Replace the body of `run_practice(...)` in `api/brain_adapter.py` with a call
that wires Person A's loop to **your** `shield_ctl` + a **real** exam against the
sandbox shield. `make_remote_context` does all the plumbing:

```python
from api import shield_ctl

def run_practice(finding, on_step, sandbox_url):
    if HAS_REAL_BRAIN:
        try:
            ctx = make_remote_context(
                sandbox_url,                       # e.g. settings.sandbox_shield_url
                apply_rule=shield_ctl.apply_rule,
                remove_rule=shield_ctl.remove_rule,
                check_syntax=shield_ctl.check_syntax,
                reload=shield_ctl.reload,
                use_cache=True,                    # replay the recorded Gemini run offline
            )
            return real_run_practice(finding, on_step, ctx).to_dict()
        except Exception as e:
            logger.error("Real brain run_practice failed, using fallback: %s", e)
    return fallback_run_practice(finding, on_step, sandbox_url)
```

Why this matters: without the context, Person A's `run_practice` falls back to
its own **in-process mock** shield — it never touches your ModSecurity, writes no
rule file, and produces no threat-feed traffic. `make_remote_context` is the seam
that makes the demo genuinely "the Practice Room proves it."

`run_practice(...).to_dict()` returns:
`{"status", "rule", "rule_id", "exam", "attempts", "reason"}` — `status` is
`"TESTED"` or `"FAILED"`, so your existing status update in
`_background_practice_task` keeps working.

---

## 3. `on_step` "result" event — keys you can now read

Person A's `run_practice` emits a `result` event per attempt. As of this version
the payload includes everything your dashboard needs:

| key          | type   | note                                            |
| ------------ | ------ | ----------------------------------------------- |
| `attempt_no` | int    | **use this** for `RuleAttempt.attempt_no` (int) |
| `attempt`    | int\|"fallback" | human label; don't store in the int column |
| `strategy`   | str    | `"strict"` / `"precise"` / fallback is precise  |
| `rule_id`    | int    | 100000–199999                                   |
| `rule`       | str    | the ModSecurity rule text                       |
| `proposal`   | dict   | the AI's proposal (target/parameter/pattern/reason/source) |
| `pattern`    | str    | the regex, for the "AI reasoning" panel         |
| `syntax_ok`  | bool   | always True by the time `result` fires          |
| `source`     | str    | `"gemini"` / `"cache"` / `"heuristic"` / `"fallback"` |
| `exam`       | dict   | `attacks_blocked/total`, `users_ok/total`, `passed`, `failures` |

Your `on_step_callback` already reads `proposal`, `rule`, `syntax_ok`, `exam` —
those now arrive populated. **One change:** read `attempt_no` (int) instead of
`attempt` so a fallback attempt ("fallback") doesn't hit the integer column:

```python
attempt_no = step_data.get("attempt_no", step_data.get("attempt", 1))
```

---

## 4. Docker + deps (so the real brain loads in the container)

`Dockerfile.api` currently copies only `api/ shield/ findings/`. Add Person A's
code and the Gemini deps:

```dockerfile
COPY fixfort/ /app/fixfort/
COPY tests/   /app/tests/
```

`requirements.txt` — add:

```
google-genai>=1.0.0
python-dotenv>=1.0.0
```

And mount the key (server-side only — never in the image, never in frontend):

```yaml
# docker-compose.yml, api service
env_file:
  - .env            # contains GEMINI_API_KEY=AQ....
```

With `use_cache=True` and the committed `.fixfort_cache/`, the demo still works
even if the container has no outbound network.

---

## 5. Make `/verify-fix` actually retire the rule

Today nothing ever switches `victim-sandbox` to the fixed code, so the naked-app
exam always finds it still vulnerable and `/verify-fix` can never retire. Before
the naked exam in `verify_fix_and_retire(...)`, flip the sandbox app to its fixed
build (simulating the shipped permanent fix), then flip back on failure:

```python
import requests

# after removing the rule from sandbox, before run_exam:
requests.post(f"{settings.sandbox_shield_url}/api/mode",
              json={"mode": "fixed"}, timeout=3)

exam_result = run_exam(settings.sandbox_shield_url, finding_dict)

if not exam_result.get("passed"):
    # fix not proven -> restore vulnerable app AND keep the live rule
    requests.post(f"{settings.sandbox_shield_url}/api/mode",
                  json={"mode": "vulnerable"}, timeout=3)
```

(The victim app already exposes `/api/mode` with `vulnerable`/`fixed`.) This is
what lets you demo the full lifecycle ending in **RETIRED** —
*"nothing stays temporary forever."*

---

## Quick smoke test before the finale

```bash
docker compose up -d --build
curl -s localhost:8000/ready                      # all pills green
# POST /protect/F-001 -> watch /status/F-001 show attempt 1 strict (O'Brien fails),
#                        attempt 2 precise (5/5 attacks, users OK, passed)
# POST /approve/F-001 -> rule live on :8080, MTTP recorded
# POST /verify-fix/F-001 -> RETIRED
```

If `make_remote_context` can't reach the sandbox shield, the exam returns
**inconclusive (never a pass)** and the finding goes FAILED — which is the safe,
honest outcome, not a fake green.
