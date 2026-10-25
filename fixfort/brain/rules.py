"""brain/rules.py — ModSecurity rule conversion and canonical patterns.

Two responsibilities:

1. Hold the canonical, hand-reviewed detection patterns for each vulnerability
   type and strategy. These are the *fallback templates* the Playbook requires,
   and they are also what the offline deterministic proposer draws on. Each one
   has been reasoned about against both the attack payloads and the legitimate
   users (see the comments and the test suite).

2. ``to_modsec(proposal, rule_id)`` — turn a validated :class:`Proposal` into a
   narrowly-scoped ModSecurity rule *string*. This function only builds text;
   it never deploys. Final syntax validation is the shield's job (``nginx -t``);
   a Python regex compiling does NOT prove the ModSecurity rule is valid.

ModSecurity assumptions (documented, v3 / CRS-style, PCRE operators):
  - Phase 2 (request body available).
  - ``REQUEST_FILENAME`` for the path, ``ARGS:<name>`` for one parameter,
    ``ARGS_NAMES`` for "this argument must not be present".
  - ``@streq`` for exact path/name match, ``@rx`` for the detection pattern.
  - ``t:none,t:urlDecodeUni,t:lowercase`` normalisation so simple case/encoding
    variations do not trivially bypass the rule. (Patterns are authored
    case-insensitively too, belt and braces.)
"""

from __future__ import annotations

import re
from typing import Optional

from .errors import RuleConversionError
from .schemas import Proposal

# Rule ids live in a private band so FixFort rules never collide with CRS
# (900000-999999) or a site's own custom rules. Person B hands out ids from
# the database; we still bound-check here.
RULE_ID_MIN = 100000
RULE_ID_MAX = 199999

MODSEC_VERSION_ASSUMPTION = "ModSecurity v3 (libmodsecurity) with PCRE @rx, phase:2"


# ---------------------------------------------------------------------------
# Canonical patterns: {vuln_type: {strategy: pattern}}
# ---------------------------------------------------------------------------
# These are deliberately conservative and finding-type specific.
#
#   strict  = block the whole suspicious *character class*. Maximum safety,
#             but it will also block some legitimate values (e.g. a quote in a
#             name, a "<" in a sentence). This is what triggers the O'Brien
#             catch on attempt 1.
#   precise = block only the injection *structures*. Stops the attacks while
#             letting legitimate values through.
#
# Every pattern is authored (?i) case-insensitive. The reasoning for why each
# precise pattern lets the known legitimate users pass is in the test suite
# (tests/test_rules.py and the exam tests).

PATTERNS: dict[str, dict[str, str]] = {
    "sqli": {
        # Strict: any single quote at all. Blocks ' OR 1=1 --  AND  O'Brien.
        "strict": r"(?i)'",
        # Precise: quote-led boolean/comment/stacked/union structures only.
        # Allows O'Brien and D'Souza (quote followed by letters, no operator).
        "precise": (
            r"(?i)("
            r"'\s*(or|and)\b"           # ' OR ... / ' AND ...
            r"|--"                       # comment
            r"|;"                        # stacked query
            r"|/\*"                      # inline comment
            r"|\bunion\b\s+\bselect\b"   # UNION SELECT
            r"|\bor\b\s+\d+\s*=\s*\d+"    # OR 1=1
            r")"
        ),
    },
    "xss": {
        # Strict: any "<". Blocks <script> AND the legitimate "5 < 6".
        "strict": r"(?i)<",
        # Precise: script/known tags, inline event handlers, javascript: URIs.
        # Allows "5 < 6, loved it" (no tag name after "<").
        "precise": (
            r"(?i)("
            r"<\s*script\b"
            r"|<\s*/?\s*(img|svg|iframe|body|a|input|details|marquee|object|embed)\b"
            r"|\bon[a-z]+\s*="          # onerror=, onload=, ...
            r"|javascript:"
            r")"
        ),
    },
    # php_rce — virtual patch for the PHP2Shell class (CVE-2026-109618/109619).
    # The permanent fix is a PHP upgrade; this shield blocks the KNOWN exploit
    # payloads reaching the PHP upload endpoint (PHP open tags, command-exec
    # functions, shell invocations) — it does not "fix" the memory bug.
    "php_rce": {
        # Strict: any PHP/shell special character. Blocks the exploit payloads,
        # but also a legitimate upload note containing "<" or "'" (the catch).
        "strict": r"(?i)[<'$\x60]",
        # Precise: actual PHP/command-execution structures only. Lets a benign
        # note like "costs 5 < 6" or a filename "O'Brien_scan.pdf" through.
        "precise": (
            r"(?i)("
            r"<\?"                               # <?php / <?= open tag
            r"|system\s*\(|passthru\s*\(|shell_exec|\bexec\s*\(|popen\s*\("
            r"|\$_(get|post|request|server|files)"
            r"|/bin/(sh|bash)"
            r"|\$\("                             # $(...) command substitution
            r"|\x60[^\x60]*\x60"                 # `...` backtick command
            r")"
        ),
    },
    # forbidden_param has no regex; the parameter must simply not exist. Both
    # strategies are identical (there is no "narrower" version of "remove it").
    "forbidden_param": {
        "strict": "",
        "precise": "",
    },
}


def pattern_for(vuln_type: str, strategy: str) -> str:
    """Return the canonical pattern for a type+strategy, or raise."""
    try:
        return PATTERNS[vuln_type][strategy]
    except KeyError as exc:
        raise RuleConversionError(
            f"no canonical pattern for type={vuln_type!r} strategy={strategy!r}"
        ) from exc


# ---------------------------------------------------------------------------
# Safe-value escaping for text that goes *inside* the rule string
# ---------------------------------------------------------------------------

def _safe_msg(text: str) -> str:
    """Make a human message safe to embed inside a single-quoted msg field.

    ModSecurity msg is single-quoted; we strip characters that could break out
    of the quoting or inject directives. We keep it readable, not lossy-free.
    """
    cleaned = re.sub(r"[^A-Za-z0-9 ._:/\-]", "", text or "")
    return cleaned[:120] if cleaned else "FixFort temporary protection"


def _validate_rule_id(rule_id: int) -> int:
    if not isinstance(rule_id, int) or isinstance(rule_id, bool):
        raise RuleConversionError(f"rule_id must be an int, got {type(rule_id).__name__}")
    if not (RULE_ID_MIN <= rule_id <= RULE_ID_MAX):
        raise RuleConversionError(
            f"rule_id {rule_id} outside FixFort band {RULE_ID_MIN}-{RULE_ID_MAX}")
    return rule_id


def _validate_path(path: str) -> str:
    # @streq compares the literal path; reject anything with quotes/spaces that
    # would need escaping and should never appear in a real endpoint anyway.
    if not re.match(r"^/[A-Za-z0-9._~\-/]{0,120}$", path or ""):
        raise RuleConversionError(f"unsafe target path for rule: {path!r}")
    return path


def _validate_ident(name: Optional[str]) -> str:
    if not name or not re.match(r"^[A-Za-z_][A-Za-z0-9_\-]{0,63}$", name):
        raise RuleConversionError(f"unsafe parameter/argument name for rule: {name!r}")
    return name


# ---------------------------------------------------------------------------
# The converter
# ---------------------------------------------------------------------------

def to_modsec(proposal: Proposal, rule_id: int) -> str:
    """Convert a validated :class:`Proposal` into a ModSecurity rule string.

    Deterministic: the same validated proposal + rule_id always yields the same
    text. Narrowly scoped: the rule only fires on the finding's exact path and
    (for rx rules) its exact parameter.

    Raises :class:`RuleConversionError` for unsafe ids, unsafe path/param
    values, or an unsupported proposal shape. Never returns an unrestricted or
    blanket rule.
    """
    if not isinstance(proposal, Proposal):
        raise RuleConversionError("to_modsec expects a validated Proposal instance")

    rid = _validate_rule_id(rule_id)
    path = _validate_path(proposal.target)
    msg = _safe_msg(proposal.reason)

    common_actions = (
        f"id:{rid},phase:2,deny,status:403,log,"
        f"t:none,t:urlDecodeUni,t:lowercase,"
        f"tag:'fixfort',msg:'{msg}'"
    )

    if proposal.kind == "forbidden":
        # "This argument must not be present." No regex on a value — we match
        # the presence of the argument NAME. Used for e.g. a debug backdoor.
        arg = _validate_ident(proposal.parameter)
        rule = (
            f'SecRule REQUEST_FILENAME "@streq {path}" '
            f'"{common_actions},chain"\n'
            f'    SecRule ARGS_NAMES "@streq {arg}" "t:none,t:lowercase"'
        )
        return rule

    # kind == "rx": match the detection pattern on exactly one parameter.
    arg = _validate_ident(proposal.parameter)
    pattern = proposal.pattern
    # Defensive: the pattern was already compile-checked in Proposal, but guard
    # against a stray double-quote that would break the ModSecurity string.
    if '"' in pattern:
        raise RuleConversionError("detection pattern may not contain a double quote")

    rule = (
        f'SecRule REQUEST_FILENAME "@streq {path}" '
        f'"{common_actions},chain"\n'
        f'    SecRule ARGS:{arg} "@rx {pattern}" "t:none,t:urlDecodeUni,t:lowercase"'
    )
    return rule


def fallback_proposal(finding) -> Proposal:
    """Return the hand-reviewed precise template proposal for a finding.

    Used by the Practice Room when the AI attempts are exhausted. It still goes
    through the exact same validation and exam — a fallback is never trusted
    blindly. Returns a :class:`Proposal`; raises RuleConversionError if the
    finding type has no template.
    """
    from .schemas import Finding  # local import to avoid cycles at module load
    if not isinstance(finding, Finding):
        raise RuleConversionError("fallback_proposal expects a Finding")

    if finding.type == "forbidden_param":
        return Proposal(
            target=finding.target,
            parameter=finding.parameter,
            strategy="precise",
            pattern="",
            reason=f"FixFort fallback: forbid argument {finding.parameter} on {finding.target}",
            kind="forbidden",
            source="fallback",
        )

    pattern = pattern_for(finding.type, "precise")
    return Proposal(
        target=finding.target,
        parameter=finding.parameter,
        strategy="precise",
        pattern=pattern,
        reason=f"FixFort fallback: precise {finding.type} template on "
               f"{finding.target}:{finding.parameter}",
        kind="rx",
        source="fallback",
    )
