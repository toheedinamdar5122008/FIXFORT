"""tests/exam.py — the exam runner (``run_exam``).

Runs the applicable attack tests and legitimate-user tests for a finding and
returns the shared :class:`ExamResult` contract. The exam is the ONLY thing
that decides a candidate is safe.

Honesty rules enforced here:
  * An attack is BLOCKED only if it returned 403 or genuinely did not succeed.
  * A legitimate user must not be 403'd and must see the expected content.
  * A transport error / timeout makes the exam INCONCLUSIVE — never passed.
  * Missing coverage (no applicable attacks or users) is inconclusive too.

Transport: pass a ``transport`` with ``send(method, path, params)`` for tests
(the in-process MockTransport). In production, omit it and a RequestsTransport
is built from ``base_url`` to talk to the sandbox shield over HTTP.
"""

from __future__ import annotations

from typing import Any, Optional

from fixfort.brain.schemas import Finding, ExamResult, Failure

from . import attacks as attacks_mod
from . import users as users_mod


def run_exam(base_url: str, finding: Any, *, transport: Optional[Any] = None,
             attack_cases: Optional[list] = None,
             user_cases: Optional[list] = None) -> ExamResult:
    if isinstance(finding, dict):
        finding = Finding.from_dict(finding)
    if not isinstance(finding, Finding):
        raise TypeError("run_exam expects a Finding or finding dict")

    if transport is None:
        from fixfort.mocks.transport import RequestsTransport
        transport = RequestsTransport(base_url)

    atk = attack_cases if attack_cases is not None else \
        attacks_mod.applicable_attacks(finding.type, finding.target)
    usr = user_cases if user_cases is not None else \
        users_mod.applicable_users(finding.target)

    failures: list[Failure] = []
    inconclusive = False

    # --- no coverage -> inconclusive, never a pass -------------------------
    if not atk or not usr:
        return ExamResult(
            attacks_blocked=0, attacks_total=len(atk),
            users_ok=0, users_total=len(usr),
            passed=False, inconclusive=True,
            failures=[Failure("error", "coverage",
                              "no applicable attack or user tests for this finding")],
        )

    # --- attacks -----------------------------------------------------------
    blocked = 0
    for a in atk:
        try:
            resp = transport.send(a.method, a.target, a.params)
        except Exception as exc:  # transport/timeout -> inconclusive
            inconclusive = True
            failures.append(Failure("error", a.id, f"transport error: {exc}"))
            continue
        status = getattr(resp, "status_code", None)
        worked = a.worked(resp)
        if status == 403 or not worked:
            blocked += 1
        else:
            failures.append(Failure("attack", a.id, "attack still succeeded", status))

    # --- legitimate users --------------------------------------------------
    users_ok = 0
    for u in usr:
        try:
            resp = transport.send(u.method, u.target, u.params)
        except Exception as exc:
            inconclusive = True
            failures.append(Failure("error", u.id, f"transport error: {exc}"))
            continue
        if u.passed(resp):
            users_ok += 1
        else:
            status = getattr(resp, "status_code", None)
            if status == 403:
                failures.append(Failure("user", u.id, "legitimate user blocked", 403))
            else:
                failures.append(Failure(
                    "user", u.id,
                    f"unexpected response, missing expected {u.expect!r}", status))

    passed = (not inconclusive
              and blocked == len(atk)
              and users_ok == len(usr))

    return ExamResult(
        attacks_blocked=blocked, attacks_total=len(atk),
        users_ok=users_ok, users_total=len(usr),
        passed=passed, inconclusive=inconclusive, failures=failures,
    )


def describe_failures(exam: ExamResult) -> str:
    """Turn exam failures into concise feedback for the next AI attempt."""
    if not exam.failures:
        return "no specific failures recorded"
    lines = []
    for f in exam.failures:
        if f.kind == "user":
            lines.append(f"Legitimate request '{f.name}' was wrongly blocked "
                         f"(got {f.got}). The rule is too broad.")
        elif f.kind == "attack":
            lines.append(f"Attack '{f.name}' still succeeded (got {f.got}). "
                         f"The rule does not cover it.")
        else:
            lines.append(f"Exam problem on '{f.name}': {f.reason}")
    return " ".join(lines)
