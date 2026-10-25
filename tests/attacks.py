"""tests/attacks.py — the security half of the exam (Person A).

Each :class:`AttackCase` is a request against the team's OWN deliberately
vulnerable local app, plus an explicit, behaviour-based way to decide whether
the attack actually *succeeded*. We never treat a 403 as proof on its own, and
we never treat an application error as proof of safety — ``worked()`` inspects
the real response.

An attack counts as BLOCKED by the exam when either:
  * the shield returned 403 (the request never reached the app), OR
  * the request reached the app but did NOT succeed (e.g. the permanent fix
    neutralised it) — this is what lets feature 3 verify a code fix.

These payloads are standard, well-known test strings used to verify defensive
WAF rules. They run only against the configured local Practice Room.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class AttackCase:
    id: str
    vuln_type: str          # "sqli" | "xss" | "forbidden_param"
    target: str             # endpoint path
    method: str             # "POST" | "GET"
    params: dict            # request parameters
    signal: str             # how to judge success: welcome|error500|reflect|unlocked
    marker: str = ""        # for reflect: the active markup that must survive

    def worked(self, resp: Any) -> bool:
        """True if the attack genuinely succeeded against the app."""
        status = getattr(resp, "status_code", None)
        text = (getattr(resp, "text", "") or "")
        if self.signal == "welcome":
            return status == 200 and "welcome" in text.lower()
        if self.signal == "error500":
            return status == 500
        if self.signal == "reflect":
            # The dangerous markup survived unescaped and would execute.
            return status == 200 and self.marker.lower() in text.lower()
        if self.signal == "unlocked":
            return status == 200 and "unlocked" in text.lower()
        if self.signal == "rce":
            # The PHP endpoint indicated the payload would execute (RCE).
            return status == 200 and "rce" in text.lower()
        return False  # unknown signal -> never silently "worked"


# --- SQL Injection against /login (parameter: username) --------------------
_SQLI = [
    AttackCase("sqli_tautology", "sqli", "/login", "POST",
               {"username": "' OR 1=1 --", "password": "x"}, "welcome"),
    AttackCase("sqli_admin_comment", "sqli", "/login", "POST",
               {"username": "admin'--", "password": "x"}, "welcome"),
    AttackCase("sqli_string_true", "sqli", "/login", "POST",
               {"username": "' OR 'a'='a", "password": "' OR 'a'='a"}, "welcome"),
    AttackCase("sqli_union", "sqli", "/login", "POST",
               {"username": "' UNION SELECT 1,'admin','x' --", "password": "x"}, "welcome"),
    AttackCase("sqli_stacked", "sqli", "/login", "POST",
               {"username": "x'; DROP TABLE users; --", "password": "x"}, "error500"),
]

# --- Cross-Site Scripting against /comment (parameter: text) ---------------
_XSS = [
    AttackCase("xss_script", "xss", "/comment", "POST",
               {"text": "<script>alert(1)</script>"}, "reflect", marker="<script"),
    AttackCase("xss_img", "xss", "/comment", "POST",
               {"text": "<img src=x onerror=alert(1)>"}, "reflect", marker="<img"),
    AttackCase("xss_svg", "xss", "/comment", "POST",
               {"text": "<svg onload=alert(1)>"}, "reflect", marker="<svg"),
    AttackCase("xss_js_link", "xss", "/comment", "POST",
               {"text": '<a href="javascript:alert(1)">hi</a>'}, "reflect", marker="<a"),
    AttackCase("xss_event_case", "xss", "/comment", "POST",
               {"text": "<IMG SRC=x OnError=alert(1)>"}, "reflect", marker="<img"),
]

# --- PHP2Shell RCE against /upload.php (parameter: note) -------------------
# CVE-2026-109618/109619. These are detection payloads for the virtual patch;
# the stand-in app reports "RCE-SIMULATED" if one would execute. No real shell.
_PHP = [
    AttackCase("php_webshell", "php_rce", "/upload.php", "POST",
               {"note": "<?php system($_GET['c']); ?>"}, "rce"),
    AttackCase("php_passthru", "php_rce", "/upload.php", "POST",
               {"note": "<?= passthru($_REQUEST['x']) ?>"}, "rce"),
    AttackCase("php_shell_exec", "php_rce", "/upload.php", "POST",
               {"note": "'; echo shell_exec('id'); //"}, "rce"),
    AttackCase("php_cmd_subst", "php_rce", "/upload.php", "POST",
               {"note": "$(/bin/sh -c id)"}, "rce"),
    AttackCase("php_backtick", "php_rce", "/upload.php", "POST",
               {"note": "`/bin/bash -c id`"}, "rce"),
]

# --- Forbidden-parameter backdoor against /unlock (argument: debug) --------
_FORBIDDEN = [
    AttackCase("unlock_debug_backdoor", "forbidden_param", "/unlock", "GET",
               {"pin": "0000", "debug": "1"}, "unlocked"),
]

ATTACKS: list[AttackCase] = _SQLI + _XSS + _PHP + _FORBIDDEN


def applicable_attacks(finding_type: str, target: str) -> list[AttackCase]:
    return [a for a in ATTACKS if a.vuln_type == finding_type and a.target == target]
