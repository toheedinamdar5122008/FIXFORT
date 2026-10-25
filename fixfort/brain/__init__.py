"""FixFort Brain package — Person A (AI & Security Engineer).

Owns the intelligence of FixFort:
  - ai.py        : turns a vulnerability finding into a candidate protective rule
  - rules.py     : converts a validated candidate into a ModSecurity rule
  - practice.py  : the Practice Room loop (propose -> test -> retry -> fallback)
  - fixes.py     : permanent code-fix guidance (separate from the WAF rule)
  - schemas.py   : typed, validated data contracts shared with Persons B and C
  - errors.py    : explicit error types for fail-closed behaviour

Design principle:
  The AI *suggests*. Deterministic Python validation and the Practice Room
  *prove*. The human *decides*. Nothing here ever deploys to the live shield.
"""

__all__ = ["ai", "rules", "practice", "fixes", "schemas", "errors"]
