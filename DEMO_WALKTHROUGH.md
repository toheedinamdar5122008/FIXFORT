# FixFort — Demo Walkthrough (Judges)

Everything below is **verified working**. It covers how the three pieces connect,
how to run it (no Docker needed), and the exact words to say on stage — for both
your classic demos (SQLi/XSS) and the headline **PHP2Shell zero-day** (CVE-2026-109618).

---

## 1. How the three layers connect (say this if asked)

```
  DASHBOARD (React, Person C)
        │  HTTP: /findings /protect /status /approve /verify-fix /events /attack
        ▼
   API  (Person B)  ──────────────►  BRAIN (Person A, fixfort.brain)
        │   orchestrates the loop       propose_rule → to_modsec → run_exam
        │                               (Gemini or deterministic), self-corrects
        ▼
   SHIELD (ModSecurity / regex)  in front of  the CLINIC APP (the vulnerable target)
```

- The **dashboard never talks to the brain directly** — it calls the **API**.
- The **API** asks the **brain** to propose a rule, applies it to the **sandbox shield**,
  and runs the **exam** (attacks + legitimate users) against the **clinic app**.
- Only a rule that passes the exam can be **approved** by a human and go **live**.
- The data on every screen is real (or clearly labelled *simulated* / *stand-in*).

---

## 2. Run it (no Docker — the stand-in path)

You don't need Docker. Two terminals from the `FixFort` folder.

**Terminal 1 — stand-in backend + clinic (API :8000, shield+clinic :8080):**
```
cd mock-backend
pip install -r requirements.txt
python server.py
```

**Terminal 2 — the dashboard:**
```
cd frontend
npm install
npm run dev
```
Open the printed localhost URL. The top bar will say **"Connected to the STAND-IN backend"** (real clinic requests and exams; the shield is a regex filter, no LLM). That's honest and fine for the demo.

> Full ModSecurity + Gemini stack: if you install Docker Desktop later, `cp .env.example .env` (add your `GEMINI_API_KEY`) then `docker compose up -d --build`. The walkthrough is identical.

---

## 3. The demo script (≈4 minutes)

Reset first: on the **Pipeline** page press **Reset demo** (clean state).

### Act 1 — The classic catch (SQLi) — proves the engine works (~90s)
1. **Command Center.** Point at the table: three findings. *"These came from a scanner. F-001 is SQL injection on a login."* Note the red **LIVE THREAT** banner up top — we'll come back to it.
2. Click **Protect** on **F-001** → you're on the **Pipeline**.
3. Press **Start protection.** Narrate as it runs:
   - *"Attempt 1 — the AI writes a strict rule. It blocks the attack… but watch —"* attempt 1 shows **FAILED: it also blocked a real user, O'Brien.** *"Our system caught its own AI's mistake."*
   - *"Attempt 2 — it narrows the rule."* → **PASSED, 5/5 attacks blocked, all users OK.**
4. Press **Approve** (the human decision) → **rule goes live, MTTP recorded in seconds.**
5. (Optional) **Live Feed** → *Send SQL injection test* = **BLOCKED**; *Log in as O'Brien* = **ALLOWED.**

### Act 2 — The headline (PHP2Shell zero-day) — proves it matters NOW (~90s)
1. Back to **Command Center.** Read the banner: *"Three days ago, CVE-2026-109618 — 'PHP2Shell' — an unauthenticated remote-code-execution bug in PHP, CVSS 9.2. ~70% of the web runs PHP. Companies are pulling sites offline. The only real fix is upgrading PHP everywhere, which takes days."*
2. *"The gap between the bug being known and PHP being upgraded is exactly what FixFort closes."* Click **Protect** on **F-004 (PHP RCE, /upload.php, Critical).**
3. **Start protection.** Same self-correcting story:
   - Attempt 1 (strict) blocks the exploit **but also a legitimate upload** ("O'Brien's scan", "5 < 6") → **FAILED.**
   - Attempt 2 (precise) → **PASSED: exploit blocked, real uploads work.**
4. **Approve** → live virtual patch in **minutes, not the days a PHP upgrade takes.**
5. **Live Feed** → *Send PHP2Shell exploit* = **BLOCKED**; *Legit file upload* = **ALLOWED.**

### Act 3 — Nothing stays temporary (~45s)
1. **Lifecycle** page. *"The shield is temporary. The real fix is upgrading PHP."* Set **Clinic code mode → fixed** (simulating the PHP upgrade).
2. Press **Verify fix and retire rule** → FixFort re-tests the app *without* the rule, sees the attack now fails on its own, and **retires the rule → RETIRED.**
3. Press **Print certificate** → the Protection Certificate (with its seal + certificate ID) — your audit trail.

### The one honest line that wins trust
> *"We don't claim our shield fixes the PHP bug — it's a memory flaw in PHP, so no WAF can. What we guarantee is different and rarer: every rule is proven against real attacks AND real users before it goes live, a human approves it, and it retires itself once the real fix is verified. SQL injection proves the engine works; this PHP zero-day proves it matters right now."*

---

## 4. If something breaks on stage
- **Dashboard says "API unreachable"** → start Terminal 1 (`python server.py`), then press **Retry**.
- **A step hangs** → press **Reset demo** on Pipeline and start again.
- **Last resort** → the dashboard's **"Use offline demo (simulated)"** button runs F-001's catch with no backend at all (clearly labelled simulated).
- Never go silent — keep narrating; the story is Problem → FixFort → Exam → O'Brien catch → minutes not weeks.

---

## 5. What's verified (so you can answer "is this real?")
- Brain: 52 unit tests pass; PHP added as a first-class finding type with its own self-correcting catch.
- Stand-in end-to-end (no Docker): F-004 goes Protect → **TESTED (strict fails 21/23 users, precise passes 23/23)** → Approve → **LIVE** → exploit **BLOCKED**, upload **ALLOWED** → Verify → **RETIRED**.
- SQLi/XSS demos unchanged and still pass.
