# FixFort: Person C completion pack

*Hackathon prototype. Not a production security product or certification.*

## 1. Audit result
**Implemented before this pass:** routing, store with three explicit data sources (real API, stand-in backend, labelled offline demo), pipeline/feed/lifecycle/certificate pages, code-built SVG hero with reduced-motion fallback, Flask clinic (vulnerable/fixed), 20 user tests, stand-in backend with real exams.
**Confirmed defects (all fixed here):**
1. Clinic reachability used `fetch(..., {mode:'no-cors'})`, which cannot read status or body, so it could not tell a clinic from any server. Now a real `GET /__health` (CORS limited to the dashboard origin, returns app name and code mode only).
2. Clinic page hardcoded the fix snippet and never showed vulnerable vs temporary vs verified state. Now driven by API workflow state; a mode mismatch between clinic and API is flagged.
3. Deep links and reloads (for example opening `/lifecycle` directly) showed empty data for about 3 s because the first refresh was skipped by a stale connection check. Fixed.
4. New CSS class `.stage` collided with the hero's `.stage` and pushed Clinic cards 80 px off screen at every width. Renamed. Long rule text in the certificate and long code in grid cells caused horizontal overflow at 390 px. Fixed (`minmax(0,1fr)`, wrapping).
5. Certificate said "Protection Certificate" even when nothing was deployed. Now reads "No certificate issued" (printing disabled) until a rule is approved; while only a temporary rule is live it states "NOT a permanent fix"; failed and rolled-back workflows are named as such.
6. Stand-in backend: health probes were logged as traffic; a `/reset` during a running Practice Room let the old thread write into fresh state. Fixed (generation counter).
7. Clinic app now refuses to serve vulnerable mode on a non-loopback address and prints a warning.
**Belongs to Person B (not done here):** real FastAPI, ModSecurity shields, `/health` on the real API, `/events` from real logs. **Person A:** LLM proposals, ModSecurity rule text, exam engine, `suggest_fix`.

## 2. Files changed
`clinic-demo/app.py` (health, CORS, loopback guard) · `clinic-demo/tests/security.py` (new) · `mock-backend/server.py` (health probes not logged, reset race, `/health.rules_live`) · `mock-backend/test_backend.py` (+12 cases) · `frontend/src/api.js` (`clinicHealth`, CONTRACTS reference) · `frontend/src/store.jsx` (boot refresh) · `frontend/src/pages/Clinic.jsx` (rewritten) · `frontend/src/pages/Lifecycle.jsx` (certificate gating) · `frontend/src/styles.css` (layout fixes) · `tests/browser-harness/` (new) · this file.

## 3. Python test suites: exact commands and verified results
Run everything from the **project root** (the folder containing `README.md`). On Windows use `py` instead of `python` if `python` is not found.
```
python -m pip install -r requirements-test.txt
python tests/run_all.py
```
`requirements-test.txt` installs Flask and requests (the live smoke test needs requests; it was previously not declared anywhere). Each script also works from any directory, for example `cd clinic-demo; python tests/users.py`.

| Suite | Command | Result (sandbox, Python 3.12, Flask 3.1, 18 Oct 2026) |
|---|---|---|
| Everything | `python tests/run_all.py` | PASS: 4 suites + 3 hygiene checks, 0 problems (also from `/` and from inside `tests/`, and with a Windows-style cp1252 console) |
| Clinic users (20 tests, both modes) | `cd clinic-demo; python tests/users.py` | PASS: vulnerable 20/20, fixed 20/20 |
| Clinic security | `cd clinic-demo; python tests/security.py` | PASS: 11/11 |
| Backend workflow, validation, rollback, reset | `cd mock-backend; python test_backend.py` | PASS: 41 checks, 0 failures |
| Live HTTP smoke (starts the server on free ports) | `python tests/live_smoke.py` | PASS: 9/9; proven not to touch a server you already run on 8000/8080 |
| Browser tests (optional) | `tests/browser-harness/*.py` | PASS 29/29 and 25/25 earlier on this code base; need Playwright (`requirements-browser.txt`) and are not part of `run_all.py` |
| Frontend `npm.cmd install` / `npm.cmd run build` / lockfile | in `frontend` | NOT RUN (no npm registry in the sandbox) |
| `scripts\verify.ps1` | PowerShell | NOT RUN |
The tests that already existed were not changed or weakened. The only environment gap found: `requests` was not declared (a clean Windows install would have failed the smoke test with ModuleNotFoundError), and the smoke test used fixed ports 8000/8080, so with your own backend running it would have talked to it and reset your demo. Both fixed.

### Start the services by hand (separate terminals, project root)
```
cd mock-backend; python server.py     # API http://localhost:8000, shielded clinic http://localhost:8080  (env FF_API_PORT, FF_LIVE_PORT to change)
cd clinic-demo; python app.py         # optional: clinic alone on http://localhost:5000 (MODE=fixed to switch; PowerShell: $env:MODE='fixed'; python app.py)
```
Health: `http://localhost:8000/health` (API), `http://localhost:8080/__health` (clinic).
Troubleshooting: `ModuleNotFoundError: flask/requests` run `python -m pip install -r requirements-test.txt`. "Port 8000/8080 is busy" run `netstat -ano | findstr :8000` then `taskkill /PID <pid> /F`. `python` not found: use `py`. Tests say MODE invalid: use exactly `vulnerable` or `fixed`.

## 4. What the demo proves, and what it does not
Proves: the workflow and UX, a real exam against a real vulnerable app (5 attacks, 20 legitimate-user tests), human-gated approval, verified retirement. Does not prove: ModSecurity-grade blocking (stand-in is a Python regex), AI quality (proposals are two fixed patterns, no LLM), or protection against attackers who bypass a regex. A temporary rule is not a fix.

## 5. API integration checklist (Person B)
- [ ] `GET /findings` rows: `id,target,parameter,type,severity,source,description,status,created_at,mttp_seconds`
- [ ] `GET /status/{id}`: `finding, step, error, attempts[], deployment{approved_by,approved_at,rolled_back_at,fix_verified_at,retired_at}, mttp_seconds`; attempts use `attempt_no,strategy,rule_text,syntax_ok,reason,failure_reason,attacks_blocked/total,users_ok/total,passed,failures[{kind,name,got}]`
- [ ] `POST /protect|approve|rollback|verify-fix/{id}` with 409 and `{error}` on invalid state; verify returns `{ok,retired,message}`
- [ ] `GET /events?since=` rows: `id,ts,method,path,query,status_code,outcome,rule_id` (+ `kind,label,worked,ok_user` for demo actions)
- [ ] `POST /attack/{sqli|xss|obrien|comment_5_lt_6}`; `GET /fix/{id}` `{before,after,explanation}`; `GET /certificate/{id}`; `POST /reset`; CORS for :5173
- [ ] A `/__health`-style endpoint on the clinic (provided in `clinic-demo/app.py`; keep it in Person C's clinic image)
- [ ] Mode switching: stand-in exposes `/demo/mode`; with the real stack switch the clinic `MODE` on both servers, then Verify
Person A needs: proposal JSON, ModSecurity text, exam result (Playbook 3.2), `suggest_fix`. Pages never call `fetch`; only `api.js` and `store.jsx` do.

## 6. Windows startup (PowerShell)
```
# Terminal 1: stand-in backend + shielded clinic (skip once Person B's stack runs)
cd mock-backend; pip install -r requirements.txt; python server.py        # API :8000, clinic :8080
# Terminal 2: dashboard
cd frontend; copy .env.example .env; npm install; npm run dev              # http://localhost:5173
# Verify before the show
cd clinic-demo; python tests/users.py; python tests/security.py
cd ..\mock-backend; python test_backend.py
cd ..\frontend; npm run build
```
Ports: 5173 dashboard, 8000 API, 8080 shielded clinic (5000 if you run the clinic alone). Env: `VITE_API_URL`, `VITE_CLINIC_URL`, `FF_CORS`, `FF_PACE`, `FF_HOST` (loopback only for vulnerable mode). No secrets are used.
**Reset:** Pipeline page, Reset demo (clears findings, rules, events, mode). MTTP starts at server start or reset, so reset right before presenting. The test suite runs its own in-process copy, so it does not need the server running.

## 7. Demo checklist (about 3 minutes)
1. Banner reads "Connected to the STAND-IN backend". Pipeline: Reset demo. Approve is disabled.
2. Clinic Demo: health pill "reachable, code mode vulnerable". Login with `' OR 1=1 --` and any password: it succeeds (the flaw).
3. Feed: Send SQL injection test: ALLOWED, ATTACK SUCCEEDED.
4. Pipeline: Start protection. Attempt 1 (strict) FAILED: 5/5 attacks, 17/20 users, blocks O'Brien. Approve still disabled. Attempt 2 (precise) PASSED 5/5 and 20/20.
5. Approve (human). Feed: SQLi BLOCKED with rule id; Log in as O'Brien ALLOWED; comment "5 < 6" ALLOWED.
6. Lifecycle: Verify fix: refused while vulnerable, rule stays. Set mode fixed, Verify: rule retired. Certificate shows RETIRED; Print.
Fallback: use "Use offline demo (simulated)" only if the API is dead and say so aloud, or play a screen recording you made earlier and label it as a recording. Record one run tonight.

## 8. Pitch script (under 3 minutes)
**0:00** "Known vulnerabilities stay open while the code fix is built. This clinic portal has a known SQL injection. Watch." (login bypass, then feed shows ALLOWED.)
**0:30** "FixFort proposes a temporary rule and tests it in a Practice Room against 5 attacks and 20 real-user cases. Attempt 1 is too broad: it blocks O'Brien. The exam catches it, and Approve stays locked."
**1:15** "Attempt 2 is narrower: 5 of 5 attacks blocked, 20 of 20 users fine. Now a human approves." (Approve; replay attack: blocked; O'Brien works.)
**1:50** "Later the developers deploy the real fix." (mode fixed, Verify.) "FixFort removes its rule, re-tests, and only then retires it. Here is the certificate."
**2:30** "In this prototype the shield is a regex stand-in and the proposals are fixed; the real design uses ModSecurity and an LLM, always behind the same exam. The AI suggests, the Practice Room proves, the human decides, and nothing stays temporary forever."
Statistic: none included. Add one only with a named credible report, year and link that you have read yourself.

## 9. Judge Q&A (honest answers)
- *Is the AI real?* Not in this build. Proposals are two fixed patterns standing in for Person A's LLM; the exam, approval and lifecycle are real.
- *Is this ModSecurity?* Not here: a Python regex shield. The contract matches the planned Nginx plus ModSecurity shield.
- *What if the rule is wrong?* The exam rejects it (shown live), a human approves, rollback is one click.
- *Can attackers bypass a regex?* Yes. That is why it is temporary and why we verify the permanent fix.
- *How do you know a rule can be removed?* We re-run the full exam without the rule on the fixed app; any surviving attack keeps the rule.
- *What data goes to an AI?* Planned: only the finding and a small code snippet, never keys or user data. Currently none.
- *Who pays?* Small teams without a security group; subscription per protected site. Unvalidated hypothesis.

## 10. Remaining limitations and recommendation
Unrun: `npm run build` and `npm run dev` on a real machine; real Person A/B integration; projector contrast. The stand-in `/attack` event attribution is not safe for concurrent users (single demo operator assumed).
**Recommendation: ready to demonstrate on the stand-in backend, provided you run `npm run build` and the three test commands on the demo laptop first and disclose the stand-in parts.** Not ready to claim real ModSecurity or AI protection until Persons A and B integrate.

## 11. Final-pass additions
- **Contact:** the placeholder `mailto:team@fixfort.example` is gone. `/contact` is a real page (roles, event, how to reach us). No team email or form is invented: optional `VITE_CONTACT_EMAIL` and `VITE_CONTACT_URL` in `frontend/.env` publish a channel after a rebuild (validated; https links only).
- **CONTRACTS.md** now exists and documents only what `mock-backend/server.py` implements.
- **Health:** the Clinic page shows two separate pills, "FixFort API" and "Clinic app", plus the protection status from the API.
- **Backend hardening:** invalid `since`, non-object JSON, injection characters in imported findings, and unknown routes now return JSON 400/404 (previously some caused 500 or HTML). Finding fields are whitelisted.
- **Windows troubleshooting:** `python` not found: try `py`. Port 8000, 8080 or 5173 busy: `netstat -ano | findstr :8000`, then `taskkill /PID <pid> /F`. Dashboard says "API unreachable": start `python server.py` first, press Retry. Clinic frame blank: open the `Open in new tab` link; confirm http://localhost:8080/__health returns JSON. PowerShell script policy blocks `npm`: use `npm.cmd`. After a server restart press Reset demo so MTTP starts fresh.
- **Commands to run on your laptop:** `cd frontend; npm.cmd install; npm.cmd run build; npm.cmd ci` then commit `package-lock.json`.

## 12. Manual QA checklist (5 minutes, on your laptop)
- [ ] `python tests/run_all.py` shows PASS everywhere; `npm.cmd run build` succeeds
- [ ] `python server.py` running; dashboard banner says STAND-IN; Reset demo
- [ ] Open each route by typing the URL, refresh, use browser Back and Forward; unknown URL shows "Page not found"
- [ ] Tab through the header: focus ring visible; Contact opens the Contact page
- [ ] Journey from section 7 (vulnerable login bypass, failed attempt 1, passing attempt 2, approve, blocked SQLi, O'Brien allowed, verify refused then retired, certificate prints on one page)
- [ ] Feed filters (All, Blocked, Attacks, Legitimate) change the list; Roll back re-exposes the app; Reset demo clears every page
- [ ] Stop the backend: banner says API unreachable and nothing is faked; Retry reconnects
Mock vs real: everything above runs on the STAND-IN (regex shield, two fixed rule patterns, no LLM, no ModSecurity). Real Person A/B modules are not in this package; see CONTRACTS.md.

## 13. Final-pass fixes and Windows one-command check
- `frontend/vite.config.js` now pins port **5173** with `strictPort` for both `npm.cmd run dev` and `npm.cmd run preview`. Before, a busy 5173 made Vite silently use 5174 and `preview` used 4173; the backend and clinic only allow the 5173 origin, so every API call and the clinic health check would have failed with a CORS error.
- Clinic: an invalid `MODE` value (for example `Fixed`) now stops the app with a clear message instead of running the fixed code under a wrong label; request bodies over 64 KB get HTTP 413.
- `scripts\verify.ps1` runs the Python checks, then `npm.cmd install`, `npm.cmd run build`, `npm.cmd ci`, `npm.cmd run build`. It was written but **not executed** (no PowerShell and no npm registry in the sandbox).
- Troubleshooting: "Port 5173 is already in use" is now an error by design: close the other Vite window or run `netstat -ano | findstr :5173` then `taskkill /PID <pid> /F`.
