"""mock_shield.py — in-process stand-in for Person B's shield-control interface.

Implements the exact contract the Practice Room depends on:

    apply_rule(env, rule_id, text)   -> stage a rule (not yet enforced)
    remove_rule(env, rule_id)        -> delete a staged/active rule
    check_syntax(env)                -> (ok: bool, error: str) over staged rules
    reload(env)                      -> activate staged rules (now enforced)

Two environments are kept completely separate: "sandbox" and "live". The
Practice Room is only ever handed the sandbox; this mock will refuse to let the
Practice Room touch "live" if asked (defence in depth for the tests).

check_syntax is a *stand-in* for ``nginx -t``: it parses FixFort's own rule
format and compile-checks the @rx pattern. It is intentionally conservative —
it rejects obviously broken rules, but the real shield's nginx -t remains the
final authority at the venue.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from ..brain.errors import ShieldInterfaceError

_PATH_RE = re.compile(r'REQUEST_FILENAME\s+"@streq\s+(\S+?)"')
_RX_RE = re.compile(r'ARGS:([A-Za-z_][A-Za-z0-9_\-]*)\s+"@rx\s+(.*?)"\s', re.DOTALL)
_FORBIDDEN_RE = re.compile(r'ARGS_NAMES\s+"@streq\s+([A-Za-z_][A-Za-z0-9_\-]*)"')
_ID_RE = re.compile(r"\bid:(\d+)\b")


@dataclass
class ParsedRule:
    rule_id: int
    target: str
    kind: str                     # "rx" or "forbidden"
    param: str
    pattern: Optional[str]        # compiled-checked regex (rx only)
    active: bool = False
    text: str = ""


@dataclass
class _Env:
    rules: dict[int, ParsedRule] = field(default_factory=dict)


class MockShield:
    def __init__(self):
        self._envs = {"sandbox": _Env(), "live": _Env()}

    # -- parsing --------------------------------------------------------------
    @staticmethod
    def _parse(rule_id: int, text: str) -> ParsedRule:
        mpath = _PATH_RE.search(text)
        if not mpath:
            raise ShieldInterfaceError("rule has no REQUEST_FILENAME @streq <path>")
        target = mpath.group(1)
        mforb = _FORBIDDEN_RE.search(text)
        if mforb:
            return ParsedRule(rule_id, target, "forbidden", mforb.group(1), None,
                              text=text)
        mrx = _RX_RE.search(text + " ")
        if not mrx:
            raise ShieldInterfaceError("rule has no recognisable ARGS:<p> @rx or "
                                       "ARGS_NAMES @streq clause")
        param, pattern = mrx.group(1), mrx.group(2).strip()
        return ParsedRule(rule_id, target, "rx", param, pattern, text=text)

    # -- contract -------------------------------------------------------------
    def apply_rule(self, env: str, rule_id: int, text: str) -> None:
        e = self._env(env)
        parsed = self._parse(rule_id, text)   # may raise -> surfaced to caller
        parsed.active = False                  # staged, not yet enforced
        e.rules[rule_id] = parsed

    def remove_rule(self, env: str, rule_id: int) -> None:
        self._env(env).rules.pop(rule_id, None)

    def check_syntax(self, env: str):
        """Return (ok, error). Compile-checks every staged rule's @rx pattern."""
        e = self._env(env)
        for rule in e.rules.values():
            if rule.kind == "rx":
                try:
                    re.compile(rule.pattern)
                except re.error as exc:
                    return False, f"rule {rule.rule_id}: bad pattern: {exc}"
                if '"' in rule.pattern:
                    return False, f"rule {rule.rule_id}: pattern contains a quote"
        return True, ""

    def reload(self, env: str) -> None:
        ok, err = self.check_syntax(env)
        if not ok:
            # Real nginx refuses to reload a broken config; so do we.
            raise ShieldInterfaceError(f"reload refused, syntax error: {err}")
        for rule in self._env(env).rules.values():
            rule.active = True

    # -- enforcement (used by the transport) ----------------------------------
    def active_rules(self, env: str) -> list[ParsedRule]:
        return [r for r in self._env(env).rules.values() if r.active]

    def _env(self, env: str) -> _Env:
        if env not in self._envs:
            raise ShieldInterfaceError(f"unknown shield env: {env!r}")
        return self._envs[env]


class SandboxOnlyShield:
    """Wrapper handed to the Practice Room: exposes only the sandbox env.

    Any attempt to drive 'live' through this wrapper raises — a hard guarantee
    that the Practice Room cannot deploy to production even by mistake.
    """

    def __init__(self, shield: MockShield):
        self._shield = shield

    def _guard(self, env: str) -> None:
        if env != "sandbox":
            raise ShieldInterfaceError(
                f"Practice Room may only use 'sandbox', refused env={env!r}")

    def apply_rule(self, env, rule_id, text):
        self._guard(env); return self._shield.apply_rule(env, rule_id, text)

    def remove_rule(self, env, rule_id):
        self._guard(env); return self._shield.remove_rule(env, rule_id)

    def check_syntax(self, env):
        self._guard(env); return self._shield.check_syntax(env)

    def reload(self, env):
        self._guard(env); return self._shield.reload(env)
