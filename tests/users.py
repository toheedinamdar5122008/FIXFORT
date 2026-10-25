"""tests/users.py — legitimate-user tests.

OWNERSHIP NOTE: this file belongs to Person C (Product & Pitch Lead). This is a
contract-compatible PLACEHOLDER so Person A can build and prove the exam and the
Practice Room offline. Person C replaces it with the full set, keeping the same
``UserCase`` shape and the ``USERS`` / ``applicable_users`` names.

Each :class:`UserCase` is a request a real user would send. It PASSES when the
shield did not block it (status != 403) and the expected content is present.
The bold cases below ("O'Brien", "D'Souza", "5 < 6") are deliberate traps that
an over-broad rule would wrongly block — they are what produce the O'Brien
catch.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class UserCase:
    id: str
    target: str
    method: str
    params: dict
    expect: str          # case-insensitive substring expected in a good response

    def passed(self, resp: Any) -> bool:
        status = getattr(resp, "status_code", None)
        text = (getattr(resp, "text", "") or "")
        if status == 403:
            return False  # a legitimate user must never be blocked
        return self.expect.lower() in text.lower()


# --- legitimate /login traffic -------------------------------------------
# Passwords MUST match the real clinic app (victim-app/app.py), or every login
# returns 401 (wrong password) and no exam can ever pass.
_LOGIN = [
    UserCase("login_alice", "/login", "POST", {"username": "alice", "password": "alicepass"},
             "welcome alice"),
    UserCase("login_admin", "/login", "POST", {"username": "admin", "password": "adminpass"},
             "welcome admin"),
    UserCase("login_obrien", "/login", "POST", {"username": "O'Brien", "password": "obrienpass"},
             "welcome o'brien"),                       # <-- apostrophe trap
    UserCase("login_dsouza", "/login", "POST", {"username": "D'Souza", "password": "dsouzapass"},
             "welcome d'souza"),                       # <-- apostrophe trap
    UserCase("login_annemarie", "/login", "POST",
             {"username": "Anne-Marie", "password": "mariypass"}, "welcome anne-marie"),
    UserCase("login_wrong_pw", "/login", "POST", {"username": "alice", "password": "nope"},
             "invalid"),                               # wrong pw -> "Invalid", not 403
]

# --- legitimate /comment traffic -------------------------------------------
_COMMENT = [
    UserCase("comment_plain", "/comment", "POST", {"text": "Great service!"},
             "great service"),
    UserCase("comment_lt", "/comment", "POST", {"text": "5 < 6, loved it"},
             "loved it"),                              # <-- "<" trap for strict XSS
    UserCase("comment_dash", "/comment", "POST",
             {"text": "Use the 2nd floor -- entrance B"}, "entrance b"),
    UserCase("comment_apostrophe", "/comment", "POST",
             {"text": "Dr. O'Brien was kind"}, "was kind"),
    UserCase("comment_its", "/comment", "POST", {"text": "It's fine"}, "it's fine"),
]

# --- legitimate /upload.php traffic (notes with "<"/"'" are strict traps) ---
_UPLOAD = [
    UserCase("upload_plain", "/upload.php", "POST", {"note": "Monthly report attached"},
             "upload received"),
    UserCase("upload_lt", "/upload.php", "POST", {"note": "Costs: 5 < 6 under budget"},
             "upload received"),                       # <-- "<" trap for strict php
    UserCase("upload_apostrophe", "/upload.php", "POST", {"note": "O'Brien's scan results"},
             "upload received"),                       # <-- apostrophe trap
    UserCase("upload_dsouza", "/upload.php", "POST", {"note": "Signed off by D'Souza"},
             "upload received"),                       # <-- apostrophe trap
    UserCase("upload_review", "/upload.php", "POST", {"note": "Please review ASAP"},
             "upload received"),
]

# --- legitimate /unlock traffic --------------------------------------------
_UNLOCK = [
    UserCase("unlock_legit", "/unlock", "GET", {"pin": "4821"}, "unlocked"),
]

USERS: list[UserCase] = _LOGIN + _COMMENT + _UPLOAD + _UNLOCK


def applicable_users(target: str) -> list[UserCase]:
    return [u for u in USERS if u.target == target]
