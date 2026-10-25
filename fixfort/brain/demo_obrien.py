"""demo_obrien.py — run the Practice Room on the SQLi finding and print the
O'Brien catch as it really happens (no hardcoding, no network).

    python demo_obrien.py
"""

from __future__ import annotations

import os
import argparse

os.environ.setdefault("FIXFORT_QUIET", "1")

# Parse the provider flag BEFORE importing the brain, so FIXFORT_FORCE_OFFLINE
# is set in time.
_parser = argparse.ArgumentParser(description="FixFort O'Brien catch demo")
_parser.add_argument("--provider", choices=["gemini", "offline"], default="offline",
                     help="offline = deterministic proposer (guaranteed clean catch, "
                          "default); gemini = use live Gemini when a key is configured")
_args, _ = _parser.parse_known_args()
if _args.provider == "offline":
    os.environ["FIXFORT_FORCE_OFFLINE"] = "1"

from fixfort.brain import practice
from fixfort.brain.schemas import Finding

FINDING = Finding("F-001", "/login", "sqli", parameter="username",
                  severity="high", source="zap",
                  description="Login query built by string concatenation")


def banner(t): print("\n" + "=" * 68 + f"\n  {t}\n" + "=" * 68)


def on_step(name, data):
    if name == "generate":
        print(f"\n-- attempt {data['attempt']} (strategy: {data['strategy']}) "
              "----------------------")
    elif name == "syntax":
        print(f"   syntax check: {'OK' if data['ok'] else 'FAIL ' + data['error']}")
    elif name == "result":
        ex = data["exam"]
        print(f"   rule id {data['rule_id']}  source={data['source']}")
        print(f"   exam -> attacks blocked {ex['attacks_blocked']}/{ex['attacks_total']}"
              f" | users OK {ex['users_ok']}/{ex['users_total']}"
              f" | passed={ex['passed']}")
        for f in ex["failures"]:
            print(f"        x {f['kind']}: {f['name']} -> {f['reason']}")
    elif name == "retry":
        print(f"   -> feeding failure back to the AI and narrowing the rule")
    elif name == "done":
        print(f"\n   DONE: status={data['status']}")


def main():
    banner("FixFort Practice Room — finding F-001 (SQL Injection on /login)")
    print(f"provider: {_args.provider}")
    # In gemini mode, run through a cache-backed local context: the first live
    # run records the real Gemini candidates, and every run after that (even with
    # no network) replays them from the cache — so the on-stage demo can't fail
    # on a flaky connection or API hiccup. Offline mode is already deterministic.
    ctx = practice.make_local_context(use_cache=True) if _args.provider == "gemini" else None
    result = practice.run_practice(FINDING, on_step, ctx)

    banner("RESULT")
    print(f"status      : {result.status}")
    print(f"attempts    : {len(result.attempts)}")
    print(f"final rule_id: {result.rule_id}")
    if result.exam:
        print(f"final exam  : attacks {result.exam.attacks_blocked}/{result.exam.attacks_total}"
              f", users {result.exam.users_ok}/{result.exam.users_total}")
    print("\nApproved-ready ModSecurity rule:\n")
    print(result.rule)
    print("\n(The approval + live deployment is Person B's endpoint — the "
          "Practice Room never deploys.)")


if __name__ == "__main__":
    main()
