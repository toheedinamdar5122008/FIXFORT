"""scripts/gemini_smoke_test.py — live Gemini connectivity check.

Run this on YOUR machine, with your own key in .env. It:
  1. confirms the google-genai SDK is installed,
  2. confirms GEMINI_API_KEY is set (it reads it from .env; never prints it),
  3. verifies GEMINI_MODEL against your account's available models,
  4. makes one tiny generation call,
and prints a PASS/FAIL report. No part of your key is ever printed.

    python scripts/gemini_smoke_test.py
"""

from __future__ import annotations

import os
import sys

# Make the project importable no matter how this script is launched (either
# `python -m scripts.gemini_smoke_test` or `python scripts/gemini_smoke_test.py`).
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from fixfort.brain import gemini_client, config


def main() -> int:
    print("FixFort — Gemini smoke test")
    print("-" * 40)
    summary = config.settings_summary()
    for k, v in summary.items():
        print(f"  {k}: {v}")
    print("-" * 40)

    report = gemini_client.smoke_test()
    for k in ("sdk_installed", "key_configured", "model", "model_supported",
              "model_detail", "generation_ok", "passed", "detail"):
        if k in report:
            print(f"  {k}: {report[k]}")
    print("-" * 40)

    if report["passed"]:
        print("RESULT: PASS — Gemini generation works. (Model listing may be "
              "blocked for new AQ. keys; that's fine — FixFort only uses "
              "generation.)")
        return 0
    print("RESULT: FAIL — see 'detail' above. FixFort still runs offline "
          "using its deterministic proposer.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
