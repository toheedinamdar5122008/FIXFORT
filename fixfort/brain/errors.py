"""Explicit error types for FixFort's Brain.

Every failure mode is named so the pipeline can behave *fail-closed*: when
something is wrong we stop and say why, rather than silently treating a
broken candidate as a safe one. These exceptions are part of the integration
contract — Person B's API maps them to clear statuses.
"""

from __future__ import annotations


class FixFortError(Exception):
    """Base class for all FixFort Brain errors."""


class FindingValidationError(FixFortError):
    """The incoming vulnerability finding is missing fields or malformed."""


class ProposalError(FixFortError):
    """The LLM (or fallback) could not produce a usable candidate proposal."""


class ProposalValidationError(ProposalError):
    """A proposal was produced but failed deterministic validation.

    Examples: target/parameter does not match the finding, the pattern does
    not compile, the pattern is empty, or the strategy is unknown.
    """


class ProviderError(ProposalError):
    """The configured LLM provider failed (timeout, HTTP error, bad JSON)."""


class GeminiError(ProviderError):
    """Base class for Google Gemini provider failures."""


class GeminiAuthError(GeminiError):
    """Authentication/permission failure (bad key). NOT retryable."""


class GeminiQuotaError(GeminiError):
    """Quota exhausted or rate limited (HTTP 429)."""


class GeminiModelError(GeminiError):
    """The configured model id is not available to this account."""


class GeminiResponseError(GeminiError):
    """The model replied, but the body was empty or not usable JSON."""


class ConfigError(FixFortError):
    """Required configuration (e.g. an API key) is missing or malformed."""


class RuleConversionError(FixFortError):
    """A validated proposal could not be converted into a ModSecurity rule.

    Raised for unsafe rule ids, unsafe values that cannot be escaped, or an
    unsupported finding type. Never results in an unrestricted rule.
    """


class ExamError(FixFortError):
    """The exam could not be completed, so its outcome is inconclusive.

    An inconclusive exam is NEVER reported as passed. Causes include a missing
    test definition, the sandbox being unreachable, or a transport timeout.
    """


class ShieldInterfaceError(FixFortError):
    """A shield-control call (apply/remove/syntax/reload) failed or is missing.

    The Practice Room only ever drives the *sandbox* shield through this
    interface; it never touches the live shield.
    """
