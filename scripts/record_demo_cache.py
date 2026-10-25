"""scripts/record_demo_cache.py — capture a REAL Gemini Practice Room run into
the on-disk candidate cache, so the live demo can replay it offline.

Why this exists
---------------
The on-stage demo must never depend on the venue Wi-Fi or a momentary API
hiccup. This script runs the full Practice Room for finding F-001 once, with
live Gemini, through the same deterministic local context the demo uses. Every
genuine Gemini candidate it produces (the strict first try AND the narrowed
precise retry — the O'Brien catch) is written to the candidate cache keyed by
(finding, strategy, feedback, prompt-version).

After this succeeds, ``python demo_obrien.py --provider gemini`` replays those
exact candidates straight from the cache — no network call is made, because
propose_rule checks the cache before the provider. The run is still a REAL
captured Gemini run, not a hardcoded script: the exam re-proves it every time.

Usage
-----
    # 1) make sure GEMINI_API_KEY is in your local .env (never paste it anywhere)
    # 2) record the cache (needs network, this one time):
    .venv/bin/python scripts/record_demo_cache.py
    # 3) prove it replays with no network:
    .venv/bin/python demo_obrien.py --provider gemini

The cache lives in the directory named by FIXFORT_CACHE_DIR (default
``.fixfort_cache``). Commit that folder so every teammate's machine is primed.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Make the project root importable no matter where this script is launched from
# (running a file inside scripts/ otherwise hides the top-level `fixfort` package).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Keep provider logs quiet; we print our own summary.
os.environ.setdefault("FIXFORT_QUIET", "1")
# Must NOT force offline — we want real Gemini output to populate the cache.
os.environ.pop("FIXFORT_FORCE_OFFLINE", None)

from fixfort.brain import ai, practice, gemini_client
from fixfort.brain.schemas import Finding

FINDING = Finding("F-001", "/login", "sqli", parameter="username",
                  severity="high", source="zap",
                  description="Login query built by string concatenation")


def main() -> int:
    if not gemini_client.gemini_available():
        print("Gemini is not available (missing SDK or GEMINI_API_KEY in .env).")
        print("Fix that first — this recorder needs a live Gemini call exactly once.")
        return 2

    cache_dir = os.environ.get("FIXFORT_CACHE_DIR", ".fixfort_cache")
    print(f"Recording a real Gemini run for {FINDING.id} into: {cache_dir}/\n")

    recorded = []

    def on_step(name, data):
        if name == "generate":
            print(f"-- attempt {data['attempt']} (strategy: {data['strategy']}) ...")
        elif name == "result":
            src = data.get("source")
            ex = data["exam"]
            tag = {"gemini": "RECORDED (fresh gemini)",
                   "cache": "ALREADY CACHED (replayed)"}.get(src, f"source={src}")
            print(f"   {tag}  pattern={data.get('pattern')!r}")
            print(f"   exam -> attacks {ex['attacks_blocked']}/{ex['attacks_total']},"
                  f" users {ex['users_ok']}/{ex['users_total']}, passed={ex['passed']}")
            # A fresh gemini call OR an existing cache hit both mean the demo is
            # primed to replay this candidate offline.
            if src in ("gemini", "cache"):
                recorded.append(data.get("pattern"))
        elif name == "done":
            print(f"\n   status={data['status']}")

    # Cache-backed local context: real exam, real Gemini, candidates cached.
    ctx = practice.make_local_context(use_cache=True)
    result = practice.run_practice(FINDING, on_step, ctx)

    print("\n" + "=" * 68)
    if result.status != "TESTED":
        print(f"Run did not reach TESTED (got {result.status}). Nothing was cached as")
        print("a verified passing sequence. Re-run once Gemini returns a clean catch.")
        return 1
    if not recorded:
        print("Run passed, but no candidate came from Gemini or the cache — it fell")
        print("back to the heuristic proposer. Check your key/model in .env, then retry.")
        return 1

    print(f"Cache is primed with {len(recorded)} Gemini-backed candidate(s).")
    print("The demo will now replay these offline (no network needed).")
    print("Verify:  python demo_obrien.py --provider gemini   (try it with Wi-Fi off)")
    print("Commit the .fixfort_cache/ folder so the whole team is primed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
