"""brain/config.py — configuration loading for FixFort.

Loads settings from the environment (and a local ``.env`` via python-dotenv if
present). The API key is read on demand and is NEVER logged, printed, cached to
disk, or included in any report. ``settings_summary()`` deliberately reports
only whether a key is present, never any part of its value.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

# Load .env if python-dotenv is available. It is optional: in CI or production
# the variables may already be in the environment.
try:  # pragma: no cover - trivial import guard
    from dotenv import load_dotenv
    load_dotenv()  # loads ./.env if it exists; never overrides real env vars
except Exception:  # pragma: no cover
    pass

# A stable, non-preview default. The live model list is the authority — the
# Gemini client verifies this id against the account's available models and
# reports clearly if it is not supported, rather than trusting this constant.
DEFAULT_GEMINI_MODEL = "gemini-3.5-flash"

# Guardrails so a prompt or a response cannot grow unbounded.
MAX_OUTPUT_TOKENS = 1024
GENERATION_TEMPERATURE = 0.0
REQUEST_TIMEOUT_S = 30.0
MAX_RETRIES = 3


@dataclass(frozen=True)
class Settings:
    gemini_model: str
    has_gemini_key: bool
    max_output_tokens: int
    temperature: float
    timeout_s: float
    max_retries: int


def get_gemini_api_key() -> Optional[str]:
    """Return the Gemini API key from the environment, or None.

    Read on demand only. The value is never logged or persisted by FixFort.
    """
    key = os.environ.get("GEMINI_API_KEY")
    return key if key and key.strip() else None


def get_gemini_model() -> str:
    return os.environ.get("GEMINI_MODEL", DEFAULT_GEMINI_MODEL).strip() or DEFAULT_GEMINI_MODEL


def load_settings() -> Settings:
    return Settings(
        gemini_model=get_gemini_model(),
        has_gemini_key=get_gemini_api_key() is not None,
        max_output_tokens=MAX_OUTPUT_TOKENS,
        temperature=GENERATION_TEMPERATURE,
        timeout_s=REQUEST_TIMEOUT_S,
        max_retries=MAX_RETRIES,
    )


def settings_summary() -> dict:
    """A secret-free view of the configuration, safe to log or show a judge."""
    s = load_settings()
    return {
        "gemini_model": s.gemini_model,
        "gemini_key_configured": s.has_gemini_key,   # bool only, never the value
        "max_output_tokens": s.max_output_tokens,
        "temperature": s.temperature,
        "timeout_s": s.timeout_s,
        "max_retries": s.max_retries,
    }
