"""Typed, validated data contracts shared across FixFort.

These mirror the formats in the Playbook (Section 3) and CONTRACTS.md. Every
object validates itself on creation, so malformed data is rejected at the
boundary rather than deep inside the pipeline. ``to_dict`` on each type
produces exactly the JSON shape Person B persists and Person C renders.

Nothing here talks to a network, a database, or a shell. Pure data + checks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

from .errors import FindingValidationError, ProposalValidationError

# ---------------------------------------------------------------------------
# Vocabulary (kept small and explicit so validation is strict)
# ---------------------------------------------------------------------------

VULN_TYPES = ("sqli", "xss", "php_rce", "forbidden_param")
STRATEGIES = ("strict", "precise")
SEVERITIES = ("low", "medium", "high", "critical")

# A conservative path shape for a demo endpoint: /login, /comment, /unlock ...
_PATH_RE = re.compile(r"^/[A-Za-z0-9._~\-/]{0,120}$")
# Parameter / argument names we are willing to reference in a rule.
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_\-]{0,63}$")
# Finding ids like F-001.
_FINDING_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,63}$")


def _require(condition: bool, message: str, exc=FindingValidationError) -> None:
    if not condition:
        raise exc(message)


# ---------------------------------------------------------------------------
# Finding — the input to FixFort (produced by a scanner / advisory)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Finding:
    """A known vulnerability FixFort will try to protect against.

    Fields match the Playbook finding format. ``parameter`` is optional only
    for ``forbidden_param`` findings where the offending argument name lives in
    ``parameter`` too (the argument that must not be present).
    """

    id: str
    target: str
    type: str
    parameter: Optional[str] = None
    severity: str = "high"
    source: str = "manual"
    description: str = ""

    def __post_init__(self) -> None:
        _require(bool(_FINDING_ID_RE.match(self.id or "")),
                 f"invalid finding id: {self.id!r}")
        _require(bool(_PATH_RE.match(self.target or "")),
                 f"invalid target path: {self.target!r}")
        _require(self.type in VULN_TYPES,
                 f"unknown vulnerability type: {self.type!r} "
                 f"(expected one of {VULN_TYPES})")
        _require(self.severity in SEVERITIES,
                 f"unknown severity: {self.severity!r}")
        if self.type in ("sqli", "xss", "php_rce"):
            _require(self.parameter is not None and bool(_IDENT_RE.match(self.parameter)),
                     f"{self.type} finding needs a valid parameter name, got {self.parameter!r}")
        if self.type == "forbidden_param":
            _require(self.parameter is not None and bool(_IDENT_RE.match(self.parameter)),
                     f"forbidden_param finding needs the forbidden argument name, got {self.parameter!r}")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        _require(isinstance(data, dict), "finding must be a dict")
        allowed = {"id", "target", "type", "parameter", "severity", "source", "description"}
        unknown = set(data) - allowed
        _require(not unknown, f"finding has unexpected fields: {sorted(unknown)}")
        return cls(
            id=data.get("id"),
            target=data.get("target"),
            type=data.get("type"),
            parameter=data.get("parameter"),
            severity=data.get("severity", "high"),
            source=data.get("source", "manual"),
            description=data.get("description", ""),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Proposal — the LLM's candidate (treated as UNTRUSTED until validated)
# ---------------------------------------------------------------------------

# Guardrail: a pattern that is too short/broad is rejected before it can ever
# reach the shield. e.g. ".*", "", "a" would blanket-block traffic.
_MIN_PATTERN_LEN = 2
_OVERBROAD_PATTERNS = {".*", ".+", "(.*)", "(.+)", "^.*$", "[\\s\\S]*"}


@dataclass(frozen=True)
class Proposal:
    """A candidate temporary protection proposed for a finding.

    ``source`` records where the candidate came from (llm / cache / fallback /
    heuristic) purely for honesty and auditing — it is never used to decide
    that a rule is safe. Only the exam decides that.
    """

    target: str
    parameter: Optional[str]
    strategy: str
    pattern: str
    reason: str
    kind: str = "rx"            # "rx" (regex match) or "forbidden" (arg must not exist)
    source: str = "llm"

    def __post_init__(self) -> None:
        _require(bool(_PATH_RE.match(self.target or "")),
                 f"proposal target invalid: {self.target!r}", ProposalValidationError)
        _require(self.strategy in STRATEGIES,
                 f"proposal strategy invalid: {self.strategy!r}", ProposalValidationError)
        _require(self.kind in ("rx", "forbidden"),
                 f"proposal kind invalid: {self.kind!r}", ProposalValidationError)
        if self.parameter is not None:
            _require(bool(_IDENT_RE.match(self.parameter)),
                     f"proposal parameter invalid: {self.parameter!r}", ProposalValidationError)
        if self.kind == "rx":
            _require(isinstance(self.pattern, str) and len(self.pattern) >= _MIN_PATTERN_LEN,
                     "proposal pattern too short", ProposalValidationError)
            _require(self.pattern not in _OVERBROAD_PATTERNS,
                     f"proposal pattern is dangerously broad: {self.pattern!r}",
                     ProposalValidationError)
            # A double quote would break out of the ModSecurity @rx string, so
            # reject it here (at proposal time) rather than later at conversion.
            # This keeps a bad LLM candidate from producing an empty attempt.
            _require('"' not in self.pattern,
                     "proposal pattern may not contain a double quote",
                     ProposalValidationError)
            # Must compile as a Python regex. (This does NOT prove the
            # ModSecurity rule is valid — the shield's syntax check does that.)
            try:
                re.compile(self.pattern)
            except re.error as exc:  # pragma: no cover - exercised in tests
                raise ProposalValidationError(f"pattern does not compile: {exc}") from exc
        _require(isinstance(self.reason, str) and self.reason.strip() != "",
                 "proposal reason must be a non-empty explanation", ProposalValidationError)

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, default_source: str = "llm") -> "Proposal":
        _require(isinstance(data, dict), "proposal must be a dict", ProposalValidationError)
        return cls(
            target=data.get("target"),
            parameter=data.get("parameter"),
            strategy=data.get("strategy", "strict"),
            pattern=data.get("pattern", ""),
            reason=data.get("reason", ""),
            kind=data.get("kind", "rx"),
            source=data.get("source", default_source),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Exam result — proof (or disproof) that a candidate is safe
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Failure:
    """One thing the exam found wrong, with enough detail to explain it."""

    kind: str          # "attack" (got through) or "user" (legit blocked) or "error"
    name: str          # the test id, e.g. "sqli_tautology" or "login_obrien"
    reason: str        # human-readable explanation
    got: Any = None    # observed status code / signal

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ExamResult:
    """The outcome of running the security + legitimate-user exam.

    ``passed`` is true ONLY when every applicable attack was neutralised AND
    every applicable legitimate user still worked AND nothing was inconclusive.
    ``inconclusive`` being true forces ``passed`` to false — an exam we could
    not complete is never reported as a success.
    """

    attacks_blocked: int
    attacks_total: int
    users_ok: int
    users_total: int
    passed: bool
    inconclusive: bool = False
    failures: list[Failure] = field(default_factory=list)

    def __post_init__(self) -> None:
        # Defensive: passing requires full coverage and no inconclusive state.
        full = (self.attacks_blocked == self.attacks_total
                and self.users_ok == self.users_total
                and self.attacks_total > 0
                and self.users_total > 0
                and not self.inconclusive)
        if self.passed and not full:
            raise ExamResultConsistencyError(
                "ExamResult marked passed but coverage/inconclusive checks disagree")

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["failures"] = [f.to_dict() if isinstance(f, Failure) else f for f in self.failures]
        return d


class ExamResultConsistencyError(FindingValidationError):
    """Raised if an ExamResult is constructed in an internally inconsistent way."""


# ---------------------------------------------------------------------------
# Practice result — what run_practice returns
# ---------------------------------------------------------------------------

# Finding status lifecycle (Playbook Section 3.5). The Brain only ever produces
# TESTED or FAILED; promotion to LIVE/RETIRED belongs to Person B's endpoints.
STATUS_TESTED = "TESTED"
STATUS_FAILED = "FAILED"


@dataclass(frozen=True)
class PracticeResult:
    """Outcome of the Practice Room loop for one finding."""

    status: str                       # STATUS_TESTED or STATUS_FAILED
    rule: Optional[str]               # the ModSecurity rule text if TESTED, else None
    rule_id: Optional[int]
    exam: Optional[ExamResult]        # evidence from the passing (or last) exam
    attempts: list[dict[str, Any]]    # ordered evidence for every attempt tried
    reason: str = ""                  # why it failed, when FAILED

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "rule": self.rule,
            "rule_id": self.rule_id,
            "exam": self.exam.to_dict() if self.exam else None,
            "attempts": self.attempts,
            "reason": self.reason,
        }


# ---------------------------------------------------------------------------
# Fix suggestion — permanent remediation guidance (NOT a WAF rule)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FixSuggestion:
    """Guidance for the permanent code fix. Advisory only; needs dev review."""

    before: str
    after: str
    explanation: str
    source: str = "llm"
    requires_review: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
