"""mock_app.py — in-process stand-in for Person C's deliberately vulnerable app.

It models just enough of the app's *observable behaviour* for the exam to tell
whether an attack actually worked, in two modes:

  MODE_VULNERABLE : the flaw is present (SQLi login bypass / stored XSS /
                    debug backdoor). Attacks succeed unless a WAF rule blocks
                    the request before it arrives.
  MODE_FIXED      : the permanent code fix is in place. Attacks no longer work
                    even with no WAF rule — this is what feature 3
                    (verify-fix-and-retire) relies on.

This is a simulation of behaviour, not a real database. The real app behaves
the same way from the outside, which is all the exam checks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

MODE_VULNERABLE = "vulnerable"
MODE_FIXED = "fixed"

# Registered legitimate users. Passwords match the real clinic app
# (victim-app/app.py) so the mock and the real target behave identically.
_USERS = {"admin": "adminpass", "alice": "alicepass", "O'Brien": "obrienpass",
          "D'Souza": "dsouzapass", "Anne-Marie": "mariypass"}

# Signatures that a naive string-built SQL login would actually be fooled by.
_SQLI_BYPASS = re.compile(
    r"('\s*or\b)|('\s*--)|(\bor\b\s+\d+\s*=\s*\d+)|(\bor\b\s+'[^']*'\s*=\s*')",
    re.IGNORECASE,
)
_SQLI_UNION = re.compile(r"\bunion\b\s+\bselect\b", re.IGNORECASE)
_SQLI_STACKED = re.compile(r";\s*\w", re.IGNORECASE)

# Markup that a browser would actually execute if rendered unescaped.
_XSS_ACTIVE = re.compile(
    r"(<\s*script\b)|(\bon[a-z]+\s*=)|(javascript:)|(<\s*(img|svg|iframe)\b)",
    re.IGNORECASE,
)

# PHP2Shell (CVE-2026-109618/109619) exploit payloads reaching the upload
# endpoint: PHP open tags, command-exec functions, shell invocations.
_PHP_RCE = re.compile(
    r"(<\?)|(system\s*\()|(passthru\s*\()|(shell_exec)|(\bexec\s*\()"
    r"|(popen\s*\()|(\$_(get|post|request|server|files))|(/bin/(sh|bash))"
    r"|(\$\()|(\x60[^\x60]*\x60)",
    re.IGNORECASE,
)


@dataclass
class Response:
    """Minimal HTTP-like response the exam can inspect (status + text)."""
    status_code: int
    text: str


class MockApp:
    def __init__(self, mode: str = MODE_VULNERABLE):
        self.mode = mode

    # -- /login ---------------------------------------------------------------
    def _login(self, params: dict) -> Response:
        user = params.get("username", "")
        pw = params.get("password", "")

        if self.mode == MODE_FIXED:
            # Parameterised query: injection is just a wrong username/password.
            if _USERS.get(user) == pw:
                return Response(200, f"Welcome {user}")
            return Response(200, "Invalid credentials")

        # VULNERABLE: naive f-string SQL. Model the real exploit outcomes.
        if _SQLI_STACKED.search(user) or _SQLI_STACKED.search(pw):
            # Stacked query -> the demo app errors out.
            return Response(500, "Internal Server Error")
        if _SQLI_UNION.search(user):
            return Response(200, "Welcome admin")
        if _SQLI_BYPASS.search(user) or _SQLI_BYPASS.search(pw):
            return Response(200, "Welcome admin")
        # Honest legitimate path still works in vulnerable mode.
        if _USERS.get(user) == pw:
            return Response(200, f"Welcome {user}")
        return Response(200, "Invalid credentials")

    # -- /comment -------------------------------------------------------------
    def _comment(self, params: dict) -> Response:
        text = params.get("text", "")
        if self.mode == MODE_FIXED:
            # Contextual escaping: the raw markup is rendered inert (escaped).
            escaped = (text.replace("&", "&amp;").replace("<", "&lt;")
                       .replace(">", "&gt;"))
            return Response(200, f"<div class='comment'>{escaped}</div>")
        # VULNERABLE: text is rendered unescaped, so active markup survives.
        return Response(200, f"<div class='comment'>{text}</div>")

    # -- /unlock (smart-lock style endpoint) ---------------------------------
    def _unlock(self, params: dict) -> Response:
        # Legitimate unlock requires the correct pin. A leftover debug arg
        # bypasses the pin check -> the vulnerability.
        pin_ok = params.get("pin") == "4821"
        if self.mode == MODE_FIXED:
            return Response(200, "UNLOCKED" if pin_ok else "DENIED")
        if "debug" in params:
            return Response(200, "UNLOCKED")  # backdoor
        return Response(200, "UNLOCKED" if pin_ok else "DENIED")

    # -- /upload.php (PHP2Shell virtual-patch target) ------------------------
    def _upload(self, params: dict) -> Response:
        note = params.get("note", "")
        is_exploit = bool(_PHP_RCE.search(note))
        if self.mode == MODE_FIXED:
            # Patched PHP runtime: the exploit payload no longer executes.
            if is_exploit:
                return Response(200, "Upload rejected: unsafe content (patched runtime)")
            return Response(200, f"Upload received: {note}")
        # VULNERABLE: an unauthenticated RCE. A weaponised note would execute.
        if is_exploit:
            return Response(200, "RCE-SIMULATED: payload would execute on the server (CVE-2026-109618)")
        return Response(200, f"Upload received: {note}")

    def handle(self, method: str, path: str, params: dict) -> Response:
        if path == "/login":
            return self._login(params)
        if path == "/comment":
            return self._comment(params)
        if path == "/unlock":
            return self._unlock(params)
        if path == "/upload.php":
            return self._upload(params)
        return Response(404, "Not Found")
