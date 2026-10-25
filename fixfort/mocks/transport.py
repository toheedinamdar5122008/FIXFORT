"""transport.py — routes exam requests through the mock shield, then the app.

The exam normally speaks HTTP to the sandbox shield. For offline, deterministic
tests we inject this transport instead: it enforces the shield's *active* rules
exactly as ModSecurity would (403 on a match), and forwards everything else to
the MockApp.

Enforcement models the documented rule transforms: urlDecode (we receive raw
values already decoded) + lowercase + case-insensitive patterns. It checks the
request path against the rule's target and applies the pattern to the one named
parameter (rx) or the presence of the argument (forbidden).
"""

from __future__ import annotations

import re
from typing import Optional

from .mock_app import MockApp, Response
from .mock_shield import MockShield


class MockTransport:
    def __init__(self, shield: MockShield, app: MockApp, env: str = "sandbox"):
        self.shield = shield
        self.app = app
        self.env = env

    def _blocked(self, path: str, params: dict) -> bool:
        for rule in self.shield.active_rules(self.env):
            if rule.target != path:
                continue
            if rule.kind == "forbidden":
                if rule.param in params:
                    return True
            else:  # rx
                value = params.get(rule.param)
                if value is None:
                    continue
                # Mirror t:lowercase + (?i): compare case-insensitively.
                if re.search(rule.pattern, str(value), re.IGNORECASE):
                    return True
        return False

    def send(self, method: str, path: str, params: Optional[dict] = None) -> Response:
        params = params or {}
        if self._blocked(path, params):
            return Response(403, "Forbidden (FixFort)")
        return self.app.handle(method, path, params)


class RequestsTransport:
    """Production transport: real HTTP to the sandbox/live shield base URL.

    Used at the venue. Kept here so run_exam has a single transport interface.
    """

    def __init__(self, base_url: str, timeout: float = 5.0):
        import requests  # imported lazily so unit tests need no network stack
        self._requests = requests
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def send(self, method: str, path: str, params: Optional[dict] = None):
        params = params or {}
        url = f"{self.base_url}{path}"
        if method.upper() == "GET":
            r = self._requests.get(url, params=params, timeout=self.timeout)
        else:
            r = self._requests.post(url, data=params, timeout=self.timeout)
        return r  # requests.Response already has .status_code and .text
