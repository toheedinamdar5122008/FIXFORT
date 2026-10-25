"""brain/practice.py — the Practice Room loop (``run_practice``).

This is the heart of FixFort and Person A's highest-priority component.

For one finding it: proposes a candidate, converts it to a ModSecurity rule,
applies it to the SANDBOX shield, syntax-checks it, reloads only on success,
runs the security + legitimate-user exam, and decides what to do next:

  * exam passes            -> return a TESTED candidate for human approval
  * exam fails (e.g. a
    legitimate user blocked) -> feed the real failure back to the AI and try a
                               narrower candidate (the O'Brien catch)
  * 3 AI attempts exhausted -> try the hand-reviewed fallback template, tested
                               the same way
  * fallback also fails     -> return FAILED. Never marked protected.

Hard guarantees:
  * It only ever drives the *sandbox* shield (through a sandbox-only wrapper).
  * A candidate that fails syntax is removed and never reaches the exam active.
  * An inconclusive exam (transport error, missing coverage) is never a pass.
  * A failing UI callback cannot bypass a security gate or cause a pass.
  * Any unexpected exception leads to a safe FAILED result and sandbox cleanup.
"""

from __future__ import annotations

import itertools
import os
from dataclasses import dataclass
from typing import Any, Callable, Optional

from . import ai as ai_mod
from . import rules as rules_mod
from .errors import (ProposalError, RuleConversionError, ShieldInterfaceError,
                     FindingValidationError)
from .schemas import (Finding, PracticeResult, ExamResult,
                      STATUS_TESTED, STATUS_FAILED)

MAX_ATTEMPTS = 3
SANDBOX_ENV = "sandbox"


# ---------------------------------------------------------------------------
# Dependency bundle (keeps the loop testable and integration-ready)
# ---------------------------------------------------------------------------

@dataclass
class PracticeContext:
    """Everything run_practice needs, injected so it can be mocked or wired to
    Person B's real shield and the real sandbox over HTTP."""

    shield: Any                                   # sandbox-only shield interface
    run_exam: Callable[[Finding], ExamResult]     # finding -> ExamResult
    next_rule_id: Callable[[], int]
    propose: Callable[..., Any] = ai_mod.propose_rule
    to_modsec: Callable[[Any, int], str] = rules_mod.to_modsec
    max_attempts: int = MAX_ATTEMPTS
    # Introspection handles (set by make_local_context; unused in production)
    raw_shield: Any = None
    app: Any = None
    transport: Any = None


def make_local_context(mode: str = "vulnerable", *, use_cache: bool = False) -> PracticeContext:
    """Build a fully in-process context (mock shield + app + transport).

    Lets the whole Practice Room run offline and deterministically. ``mode`` is
    "vulnerable" or "fixed" (the latter is used to demonstrate verify-fix).
    """
    from ..mocks.mock_shield import MockShield, SandboxOnlyShield
    from ..mocks.mock_app import MockApp
    from ..mocks.transport import MockTransport
    from tests.exam import run_exam as exam_run

    raw = MockShield()
    sandbox_shield = SandboxOnlyShield(raw)
    app = MockApp(mode)
    transport = MockTransport(raw, app, SANDBOX_ENV)
    counter = itertools.count(100001)

    def _exam(finding: Finding) -> ExamResult:
        return exam_run("mock://sandbox", finding, transport=transport)

    def _propose(finding, feedback=None, strategy="strict"):
        return ai_mod.propose_rule(finding, feedback, strategy, use_cache=use_cache)

    return PracticeContext(
        shield=sandbox_shield, run_exam=_exam, next_rule_id=lambda: next(counter),
        propose=_propose, raw_shield=raw, app=app, transport=transport,
    )


# ---------------------------------------------------------------------------
# Production seam: wire the loop to Person B's REAL ModSecurity sandbox
# ---------------------------------------------------------------------------

class _RemoteSandboxShield:
    """Adapts Person B's shield-control callables to the sandbox-only shield
    interface the Practice Room expects.

    Person B's ``shield_ctl`` functions take ``env`` first and return either a
    ``(ok, error)`` tuple (``check_syntax``/``reload``) or a truthy value / raise
    (``apply_rule``/``remove_rule``). This wrapper normalises both conventions to
    what :func:`run_practice` needs — apply/reload raise
    :class:`ShieldInterfaceError` on failure, ``check_syntax`` returns
    ``(ok, error)`` — and hard-refuses any env other than ``"sandbox"`` so the
    loop can never touch the live shield.
    """

    def __init__(self, *, apply_rule, remove_rule, check_syntax, reload):
        self._apply = apply_rule
        self._remove = remove_rule
        self._check = check_syntax
        self._reload = reload

    def _guard(self, env: str) -> None:
        if env != SANDBOX_ENV:
            raise ShieldInterfaceError(
                f"Practice Room may only use 'sandbox', refused env={env!r}")

    @staticmethod
    def _ok_err(result) -> tuple[bool, str]:
        """Normalise a callable's return to ``(ok, error)``.

        Accepts a ``(ok, error)`` tuple, ``None`` (success), or any truthy/falsy
        value, so it works whether Person B returns a bool or a tuple.
        """
        if isinstance(result, tuple) and len(result) == 2:
            return bool(result[0]), str(result[1] or "")
        if result is None:
            return True, ""
        return bool(result), ""

    def apply_rule(self, env, rule_id, text):
        self._guard(env)
        try:
            ok, err = self._ok_err(self._apply(env, rule_id, text))
        except ShieldInterfaceError:
            raise
        except Exception as exc:
            raise ShieldInterfaceError(f"apply_rule failed: {exc}") from exc
        if not ok:
            raise ShieldInterfaceError(f"apply_rule refused: {err}")

    def remove_rule(self, env, rule_id):
        self._guard(env)
        try:
            self._remove(env, rule_id)
        except Exception:  # pragma: no cover - best-effort cleanup (mirrors mock)
            pass

    def check_syntax(self, env):
        self._guard(env)
        try:
            return self._ok_err(self._check(env))
        except Exception as exc:  # an unusable syntax check is NOT a pass
            return False, f"check_syntax error: {exc}"

    def reload(self, env):
        self._guard(env)
        try:
            ok, err = self._ok_err(self._reload(env))
        except ShieldInterfaceError:
            raise
        except Exception as exc:
            raise ShieldInterfaceError(f"reload failed: {exc}") from exc
        if not ok:
            raise ShieldInterfaceError(f"reload refused: {err}")


def make_remote_context(sandbox_url: str, *, apply_rule, remove_rule,
                        check_syntax, reload, run_exam=None,
                        start_rule_id: int = 100001,
                        use_cache: bool = True) -> PracticeContext:
    """Build a :class:`PracticeContext` wired to Person B's REAL sandbox shield.

    This is the production seam that makes the live path genuinely *proven*, not
    simulated: the AI (Gemini, or the deterministic proposer) proposes a
    candidate, it is converted to a ModSecurity rule, applied to Person B's
    sandbox shield through ``apply_rule``/``check_syntax``/``reload``, and then
    tested with a REAL HTTP exam against ``sandbox_url``. Only the exam's verdict
    decides TESTED vs FAILED — nothing is hardcoded.

    Person B wires it in one call::

        from fixfort.brain.practice import run_practice, make_remote_context
        from api import shield_ctl
        from api.config import settings

        ctx = make_remote_context(
            settings.sandbox_shield_url,
            apply_rule=shield_ctl.apply_rule,
            remove_rule=shield_ctl.remove_rule,
            check_syntax=shield_ctl.check_syntax,
            reload=shield_ctl.reload,
        )
        result = run_practice(finding_dict, on_step_callback, ctx)

    Parameters
    ----------
    sandbox_url : str
        Base URL of the sandbox shield (e.g. ``http://shield-sandbox:80``). The
        exam sends real HTTP attacks and legitimate-user requests here.
    apply_rule, remove_rule, check_syntax, reload : callables
        Person B's ``shield_ctl`` functions. Each takes ``env`` first.
    run_exam : callable, optional
        Override the exam runner ``run_exam(base_url, finding)``. Defaults to
        :func:`tests.exam.run_exam`, which talks real HTTP to ``sandbox_url``.
    start_rule_id : int
        First rule id to allocate (FixFort range 100000–199999).
    use_cache : bool
        Read/write the candidate cache so a captured Gemini run can be replayed
        offline at the venue.
    """
    shield = _RemoteSandboxShield(
        apply_rule=apply_rule, remove_rule=remove_rule,
        check_syntax=check_syntax, reload=reload)

    if run_exam is None:
        from tests.exam import run_exam as _exam_run
    else:
        _exam_run = run_exam

    def _exam(finding: Finding) -> ExamResult:
        return _exam_run(sandbox_url, finding)

    def _propose(finding, feedback=None, strategy="strict"):
        return ai_mod.propose_rule(finding, feedback, strategy, use_cache=use_cache)

    counter = itertools.count(start_rule_id)
    return PracticeContext(
        shield=shield, run_exam=_exam, next_rule_id=lambda: next(counter),
        propose=_propose,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _emit(on_step: Optional[Callable[[str, dict], None]], name: str, data: dict) -> None:
    """Emit a pipeline event. A broken callback is logged, never fatal, and can
    never influence a security decision."""
    if on_step is None:
        return
    try:
        on_step(name, data)
    except Exception as exc:  # pragma: no cover - defensive
        if os.environ.get("FIXFORT_QUIET") != "1":
            print(f"[fixfort.practice] on_step({name}) callback failed: {exc}")


def _safe_remove(ctx: PracticeContext, rule_id: Optional[int]) -> None:
    if rule_id is None:
        return
    try:
        ctx.shield.remove_rule(SANDBOX_ENV, rule_id)
    except Exception:  # pragma: no cover - best-effort cleanup
        pass


def _test_candidate(ctx: PracticeContext, finding: Finding, proposal, rule_id: int,
                    on_step, attempt_label) -> tuple[Optional[ExamResult], Optional[str], Optional[str]]:
    """Apply -> syntax-check -> reload -> exam for one candidate.

    Returns (exam_result, rule_text, error). Exactly one of exam_result/error
    is non-None. On any syntax/apply problem the candidate is removed so it
    never stays active in the sandbox.
    """
    try:
        rule_text = ctx.to_modsec(proposal, rule_id)
    except RuleConversionError as exc:
        return None, None, f"rule conversion failed: {exc}"

    try:
        ctx.shield.apply_rule(SANDBOX_ENV, rule_id, rule_text)
    except ShieldInterfaceError as exc:
        return None, rule_text, f"sandbox apply failed: {exc}"

    ok, err = ctx.shield.check_syntax(SANDBOX_ENV)
    _emit(on_step, "syntax", {"attempt": attempt_label, "ok": ok, "error": err})
    if not ok:
        _safe_remove(ctx, rule_id)   # never let a broken rule reach the exam active
        return None, rule_text, f"syntax check failed: {err}"

    try:
        ctx.shield.reload(SANDBOX_ENV)
    except ShieldInterfaceError as exc:
        _safe_remove(ctx, rule_id)
        return None, rule_text, f"sandbox reload failed: {exc}"

    _emit(on_step, "exam", {"attempt": attempt_label})
    exam = ctx.run_exam(finding)
    return exam, rule_text, None


# ---------------------------------------------------------------------------
# Public contract
# ---------------------------------------------------------------------------

def run_practice(finding: Any, on_step: Optional[Callable[[str, dict], None]] = None,
                 context: Optional[PracticeContext] = None) -> PracticeResult:
    """Run the Practice Room for one finding and return a :class:`PracticeResult`.

    ``context`` must be provided in production (wired to Person B's sandbox). If
    omitted, a local in-process context is built so the loop is runnable and
    demonstrable offline.
    """
    if isinstance(finding, dict):
        finding = Finding.from_dict(finding)
    if not isinstance(finding, Finding):
        raise FindingValidationError("run_practice expects a Finding or finding dict")

    ctx = context or make_local_context()
    attempts: list[dict] = []
    last_exam: Optional[ExamResult] = None
    current_rule_id: Optional[int] = None

    _emit(on_step, "start", {"finding": finding.id, "type": finding.type,
                             "target": finding.target, "parameter": finding.parameter})

    try:
        feedback: Optional[str] = None
        strategy = "strict"

        for attempt in range(1, ctx.max_attempts + 1):
            _emit(on_step, "generate", {"attempt": attempt, "strategy": strategy})
            rule_id = ctx.next_rule_id()
            current_rule_id = rule_id

            # --- propose + validate -------------------------------------
            try:
                proposal = ctx.propose(finding, feedback, strategy)
            except ProposalError as exc:
                attempts.append({"attempt": attempt, "strategy": strategy,
                                 "status": "proposal_error", "error": str(exc)})
                feedback = f"Previous proposal was rejected: {exc}. Try again, narrower."
                strategy = "precise"
                continue

            # --- apply + syntax + reload + exam -------------------------
            exam, rule_text, err = _test_candidate(
                ctx, finding, proposal, rule_id, on_step, attempt)

            if err is not None:
                attempts.append({"attempt": attempt, "strategy": strategy,
                                 "rule_id": rule_id, "source": proposal.source,
                                 "status": "candidate_error", "error": err})
                feedback = err
                strategy = "precise"
                _safe_remove(ctx, rule_id)
                continue

            last_exam = exam
            evidence = {"attempt": attempt, "attempt_no": attempt,
                        "strategy": strategy, "rule_id": rule_id,
                        "rule": rule_text, "source": proposal.source,
                        "proposal": proposal.to_dict(), "pattern": proposal.pattern,
                        "syntax_ok": True, "exam": exam.to_dict()}
            attempts.append(evidence)
            _emit(on_step, "result", evidence)

            if exam.passed:
                _safe_remove(ctx, rule_id)  # keep sandbox clean; approval re-applies to live
                _emit(on_step, "done", {"status": STATUS_TESTED, "attempt": attempt})
                return PracticeResult(STATUS_TESTED, rule_text, rule_id, exam, attempts, "")

            # exam failed -> evidence-driven retry, narrower
            from tests.exam import describe_failures
            feedback = describe_failures(exam)
            _safe_remove(ctx, rule_id)
            _emit(on_step, "retry", {"attempt": attempt, "feedback": feedback})
            strategy = "precise"

        # --- AI attempts exhausted: hand-reviewed fallback --------------
        _emit(on_step, "fallback", {"after_attempts": ctx.max_attempts})
        rule_id = ctx.next_rule_id()
        current_rule_id = rule_id
        try:
            fb_proposal = rules_mod.fallback_proposal(finding)
        except RuleConversionError as exc:
            return PracticeResult(STATUS_FAILED, None, None, last_exam, attempts,
                                  f"no fallback template available: {exc}")

        exam, rule_text, err = _test_candidate(
            ctx, finding, fb_proposal, rule_id, on_step, "fallback")
        if err is not None:
            _safe_remove(ctx, rule_id)
            attempts.append({"attempt": "fallback", "rule_id": rule_id,
                             "source": "fallback", "status": "candidate_error",
                             "error": err})
            return PracticeResult(STATUS_FAILED, None, None, last_exam, attempts,
                                  f"fallback candidate error: {err}")

        last_exam = exam
        evidence = {"attempt": "fallback", "attempt_no": ctx.max_attempts + 1,
                    "strategy": "precise", "rule_id": rule_id, "rule": rule_text,
                    "source": "fallback", "proposal": fb_proposal.to_dict(),
                    "pattern": fb_proposal.pattern, "syntax_ok": True,
                    "exam": exam.to_dict()}
        attempts.append(evidence)
        _emit(on_step, "result", evidence)
        _safe_remove(ctx, rule_id)

        if exam.passed:
            _emit(on_step, "done", {"status": STATUS_TESTED, "attempt": "fallback"})
            return PracticeResult(STATUS_TESTED, rule_text, rule_id, exam, attempts, "")

        _emit(on_step, "done", {"status": STATUS_FAILED, "attempt": "fallback"})
        return PracticeResult(STATUS_FAILED, None, None, exam, attempts,
                              "fallback template did not pass the exam")

    except Exception as exc:  # pragma: no cover - last-resort fail-closed
        _safe_remove(ctx, current_rule_id)
        _emit(on_step, "error", {"message": str(exc)})
        return PracticeResult(STATUS_FAILED, None, None, last_exam, attempts,
                              f"unexpected error, failing closed: {exc}")
    finally:
        _safe_remove(ctx, current_rule_id)
