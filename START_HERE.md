# FixFort — Combined Repo (Brain + Backend + Frontend)

**Hackyard Build 2026 · IIT Guwahati.** This is the single, integrated FixFort
repository: Person A's AI brain, Person B's API + shields + victim app, and
Person C's dashboard, wired together and verified.

> Motto: *"The AI suggests, the Practice Room proves, the human decides, and nothing stays temporary forever."*

---

## What's inside

```
FixFort/
├── fixfort/          Person A — the AI brain (fixfort.brain.*)
├── tests/            Person A's exam/attacks/users + Person B's API tests
├── api/              Person B — FastAPI app, shield control, lifecycle
├── shield/           Person B — Nginx + ModSecurity configs & rules
├── victim-app/       Person B — the vulnerable clinic (the real target)
├── findings/         Person B — seed findings (F-001 …)
├── frontend/         Person C — React dashboard (polished)
├── clinic-demo/      Person C — standalone clinic (frontend dev stand-in)
├── mock-backend/     Person C — stand-in API (frontend dev without the full stack)
├── demo_obrien.py    Person A — the O'Brien-catch CLI demo
├── scripts/          Person A — record_demo_cache.py (network-proof demo)
├── docker-compose.yml  the full stack
├── INTEGRATION.md    how the brain plugs into the backend (reference)
└── .env.example      copy to .env and fill in GEMINI_API_KEY
```

The integration is **done**: the API imports the real brain as `fixfort.brain`,
and `api/brain_adapter.py` wires Gemini → ModSecurity rule → **our real sandbox
shield** → **real HTTP exam** via `make_remote_context`. Verified: the brain's
52 unit tests pass in this layout, and the adapter loads with
`HAS_REAL_BRAIN = True`.

---

## Run it — the full stack (for the demo)

Needs Docker Desktop.

```bash
cp .env.example .env            # then put your GEMINI_API_KEY in .env (local only)
docker compose up -d --build
```

- API: http://localhost:8000  (check http://localhost:8000/ready)
- Live shield (protected clinic): http://localhost:8080
- Sandbox shield (Practice Room): http://localhost:8081

Then run the dashboard:

```bash
cd frontend
cp .env.example .env            # VITE_API_URL defaults to http://localhost:8000
npm install
npm run dev                     # open the printed localhost URL
```

Demo flow on the dashboard: **Command Center** → Protect F-001 → watch the
**Pipeline** show attempt 1 (strict, blocks O'Brien → fails) then attempt 2
(precise → 5/5 attacks, users OK → passes) → **Approve** → rule live, MTTP
recorded → **Lifecycle** → Verify fix → RETIRED, and print the certificate.

---

## Run it — frontend only (no Docker, for UI work)

Two terminals:

```bash
cd mock-backend && pip install -r requirements.txt && python server.py   # stand-in API + clinic
cd frontend && npm install && npm run dev
```

The dashboard clearly labels this as the **stand-in backend** (real exams, regex
shield, fixed proposals — no LLM, no ModSecurity).

---

## Run it — the brain alone (Person A)

```bash
cd .  # repo root
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m unittest tests.test_fixfort tests.test_gemini     # 52 tests
python demo_obrien.py --provider offline                    # guaranteed O'Brien catch
python demo_obrien.py --provider gemini                     # live Gemini (needs key in .env)
python scripts/record_demo_cache.py                         # cache a real Gemini run (network-proof)
```

---

## Notes for the team

- **Gemini key** lives only in your local `.env` (git-ignored). Never commit it,
  never paste it in chat. With a cached run committed in `.fixfort_cache/`, the
  demo replays offline if the venue network fails.
- **Verify-fix** now flips the sandbox app to its fixed build before the naked
  exam, so the lifecycle can actually reach **RETIRED** on stage.
- If `HAS_REAL_BRAIN` ever logs `False`, the `fixfort/` and `tests/` folders
  aren't on the API's path — check the `COPY fixfort/ /app/fixfort/` and
  `COPY tests/ /app/tests/` lines in `Dockerfile.api`.
- One cosmetic gap: the dashboard's embedded-clinic health dot expects
  `/__health`; Person B's victim app serves `/health`. The dot staying grey
  doesn't affect the real workflow (protection status comes from the API).
