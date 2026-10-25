"""brain/gemini_client.py — Google Gemini provider via the official google-genai SDK.

Thin, defensive wrapper used by ai.py and fixes.py. Responsibilities:

  * lazily import ``google-genai`` so the rest of FixFort runs without the SDK;
  * build a client from ``GEMINI_API_KEY`` (never logged);
  * verify the configured model against the account's actual model list;
  * generate JSON with low-variance settings, bounded output, and bounded
    retries with backoff — never retrying non-recoverable auth errors;
  * map provider failures to FixFort's typed errors;
  * expose a secret-free ``smoke_test()`` for a live connectivity check.

This module decides nothing about security. It only fetches a candidate. All
validation and the Practice Room exam remain the authority (ai.py / practice.py).
"""

from __future__ import annotations

import json
import random
import time
from typing import Any, Optional

from . import config
from .errors import (GeminiError, GeminiAuthError, GeminiQuotaError,
                     GeminiModelError, GeminiResponseError, ConfigError)

_client_cache: dict[str, Any] = {}


# ---------------------------------------------------------------------------
# Availability / client
# ---------------------------------------------------------------------------

def sdk_available() -> bool:
    """True if the google-genai SDK can be imported in this environment."""
    try:
        import google.genai  # noqa: F401
        return True
    except Exception:
        return False


def gemini_available() -> bool:
    """True if both a key is configured AND the SDK is importable."""
    return config.get_gemini_api_key() is not None and sdk_available()


def _get_client():
    """Build (and cache) a genai.Client from the configured key.

    Raises ConfigError if the key is missing, GeminiError if the SDK is absent.
    """
    key = config.get_gemini_api_key()
    if key is None:
        raise ConfigError("GEMINI_API_KEY is not set")
    if not sdk_available():
        raise GeminiError("google-genai SDK is not installed")
    cache_key = str(id(key))  # do not key the cache on the secret value itself
    if cache_key not in _client_cache:
        from google import genai
        _client_cache[cache_key] = genai.Client(api_key=key)
    return _client_cache[cache_key]


# ---------------------------------------------------------------------------
# Error classification
# ---------------------------------------------------------------------------

def _status_code(exc: Exception) -> Optional[int]:
    for attr in ("code", "status_code", "http_status"):
        val = getattr(exc, attr, None)
        if isinstance(val, int):
            return val
    return None


def _classify(exc: Exception) -> str:
    """Return one of: auth | quota | model | transient | fatal.

    Based on HTTP status where available, else the exception text. No secrets
    are ever read from the exception.
    """
    code = _status_code(exc)
    text = f"{type(exc).__name__}: {exc}".lower()
    if code in (401, 403) or "unauthenticated" in text or "permission" in text \
            or "api key" in text or "api_key" in text:
        return "auth"
    if code == 429 or "quota" in text or "rate limit" in text or "resource_exhausted" in text:
        return "quota"
    if code == 404 or "not found" in text or "not supported" in text:
        return "model"
    if code in (500, 502, 503, 504) or "timeout" in text or "timed out" in text \
            or "deadline" in text or "unavailable" in text or "connection" in text:
        return "transient"
    return "fatal"


def _raise_mapped(exc: Exception) -> None:
    kind = _classify(exc)
    code = _status_code(exc)
    where = f" (HTTP {code})" if code else ""
    if kind == "auth":
        raise GeminiAuthError(f"Gemini authentication failed{where}: check GEMINI_API_KEY") from exc
    if kind == "quota":
        raise GeminiQuotaError(f"Gemini quota/rate limit hit{where}") from exc
    if kind == "model":
        raise GeminiModelError(f"Gemini model unavailable{where}") from exc
    raise GeminiError(f"Gemini request failed{where}: {type(exc).__name__}") from exc


# ---------------------------------------------------------------------------
# Model verification
# ---------------------------------------------------------------------------

def list_models() -> list[str]:
    """Return available model ids (short form, e.g. 'gemini-2.5-flash')."""
    client = _get_client()
    try:
        names = []
        for m in client.models.list():
            name = getattr(m, "name", "") or ""
            names.append(name.split("/")[-1] if name else "")
        return [n for n in names if n]
    except Exception as exc:  # noqa: BLE001
        _raise_mapped(exc)
        return []  # unreachable


def verify_model(model: Optional[str] = None) -> tuple[bool, str, list[str]]:
    """Check the configured model against the account's live model list.

    Returns (ok, message, available_models). Never raises for a simple
    unsupported-model case; it reports it so the caller can decide.
    """
    model = model or config.get_gemini_model()
    try:
        available = list_models()
    except GeminiError as exc:
        return False, f"could not list models: {exc}", []
    short = {m.split("/")[-1] for m in available}
    if model in short:
        return True, f"model '{model}' is available", available
    return (False,
            f"model '{model}' is NOT in this account's available models",
            available)


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------

def generate_json(system: str, user: str, *, schema: Optional[dict] = None,
                  model: Optional[str] = None) -> dict:
    """Generate a JSON object from Gemini with low-variance settings.

    Bounded retries with backoff for transient/quota errors; auth and model
    errors are raised immediately (not retryable). Returns a parsed dict.
    Raises a GeminiError subclass on failure. No secrets are logged.
    """
    client = _get_client()
    settings = config.load_settings()
    model = model or settings.gemini_model

    last_exc: Optional[Exception] = None
    for attempt in range(1, settings.max_retries + 1):
        try:
            text = _generate_once(client, model, system, user, schema, settings)
        except Exception as exc:  # noqa: BLE001
            kind = _classify(exc)
            if kind in ("auth", "model"):
                _raise_mapped(exc)         # non-recoverable: do not retry
            last_exc = exc
            if attempt < settings.max_retries:
                _backoff(attempt)
                continue
            _raise_mapped(exc)
        # got a response body
        if not text.strip():
            last_exc = GeminiResponseError("empty response body")
            if attempt < settings.max_retries:
                _backoff(attempt)
                continue
            raise last_exc
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise GeminiResponseError(f"response was not valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise GeminiResponseError("response JSON was not an object")
        return data

    # Defensive: loop always returns or raises above.
    raise GeminiError(f"Gemini generation failed: {last_exc}")


def _generate_once(client, model: str, system: str, user: str,
                   schema: Optional[dict], settings) -> str:
    """One raw generation call. Isolated so retry/backoff/classification can be
    tested without the SDK (tests patch this function)."""
    from google.genai import types  # lazy: only needed on the live path

    cfg_kwargs: dict[str, Any] = dict(
        system_instruction=system,
        temperature=settings.temperature,
        max_output_tokens=settings.max_output_tokens,
        response_mime_type="application/json",
    )
    if schema is not None:
        cfg_kwargs["response_schema"] = schema
    try:
        gen_config = types.GenerateContentConfig(**cfg_kwargs)
    except Exception:
        # SDK rejected the schema shape -> degrade to mime-type-only JSON.
        gen_config = types.GenerateContentConfig(
            system_instruction=system, temperature=settings.temperature,
            max_output_tokens=settings.max_output_tokens,
            response_mime_type="application/json")
    resp = client.models.generate_content(model=model, contents=user, config=gen_config)
    return getattr(resp, "text", None) or ""


def _backoff(attempt: int) -> None:
    delay = min(0.5 * (2 ** (attempt - 1)), 8.0) + random.uniform(0, 0.25)
    time.sleep(delay)


# ---------------------------------------------------------------------------
# Live smoke test (secret-free report)
# ---------------------------------------------------------------------------

def smoke_test() -> dict:
    """Minimal end-to-end connectivity check. Returns a report dict.

    Does NOT raise; it reports success or the reason for failure, with no key
    material anywhere in the output.
    """
    report: dict[str, Any] = {
        "sdk_installed": sdk_available(),
        "key_configured": config.get_gemini_api_key() is not None,
        "model": config.get_gemini_model(),
        "model_supported": None,
        "generation_ok": None,
        "passed": False,
        "detail": "",
    }
    if not report["sdk_installed"]:
        report["detail"] = "google-genai not installed (pip install google-genai)"
        return report
    if not report["key_configured"]:
        report["detail"] = "GEMINI_API_KEY not set in environment/.env"
        return report

    # Model listing is best-effort. The new "AQ." auth keys frequently reject
    # models.list() with 401 while still working fine for generate_content —
    # and generation is the ONLY call FixFort actually uses. So a failed list
    # must NOT fail the smoke test; we go straight to a real generation call.
    try:
        ok, msg, _ = verify_model()
        report["model_supported"] = ok
        report["model_detail"] = msg
    except Exception as exc:  # noqa: BLE001
        report["model_supported"] = None
        report["model_detail"] = f"model list unavailable ({exc}); testing generation directly"

    try:
        data = generate_json(
            system="Reply with a single JSON object.",
            user='Return exactly {"ping": "pong"}.',
        )
        report["generation_ok"] = bool(data)
        report["passed"] = bool(data)
        report["detail"] = ("connectivity verified via a real generation call"
                            if report["passed"]
                            else "model replied but content was empty")
    except GeminiError as exc:
        report["detail"] = f"generation failed: {type(exc).__name__}: {exc}"
    return report
