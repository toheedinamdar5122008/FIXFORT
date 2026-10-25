"""Mocked Gemini-integration tests — run with NO key and NO SDK:

    python -m unittest tests.test_gemini -v

These exercise retry/backoff, error classification, model verification, and the
all-important fallback behaviour (a provider failure must degrade to the
deterministic proposer, never a false success). The real network call path is
covered by the live smoke test (scripts/gemini_smoke_test.py).
"""

from __future__ import annotations

import os
import unittest
from unittest import mock

os.environ.setdefault("FIXFORT_QUIET", "1")

from fixfort.brain import gemini_client, ai, fixes, config
from fixfort.brain.errors import (GeminiAuthError, GeminiResponseError, GeminiError)
from fixfort.brain.schemas import Finding

SQLI = Finding("F-001", "/login", "sqli", parameter="username")
GOOD = {"target": "/login", "parameter": "username", "strategy": "precise",
        "pattern": r"(?i)('\s*or\b|--|;)", "reason": "block sqli structures"}


class FakeExc(Exception):
    def __init__(self, msg, code=None):
        super().__init__(msg); self.code = code


class TestClassify(unittest.TestCase):
    def test_codes(self):
        self.assertEqual(gemini_client._classify(FakeExc("x", 401)), "auth")
        self.assertEqual(gemini_client._classify(FakeExc("x", 429)), "quota")
        self.assertEqual(gemini_client._classify(FakeExc("x", 404)), "model")
        self.assertEqual(gemini_client._classify(FakeExc("x", 503)), "transient")
        self.assertEqual(gemini_client._classify(FakeExc("weird")), "fatal")

    def test_text_fallback(self):
        self.assertEqual(gemini_client._classify(Exception("Invalid API key")), "auth")
        self.assertEqual(gemini_client._classify(Exception("quota exceeded")), "quota")


class TestGenerateJson(unittest.TestCase):
    def setUp(self):
        self._get = mock.patch.object(gemini_client, "_get_client", lambda: object())
        self._bk = mock.patch.object(gemini_client, "_backoff", lambda n: None)
        self._get.start(); self._bk.start()

    def tearDown(self):
        self._get.stop(); self._bk.stop()

    def test_success(self):
        with mock.patch.object(gemini_client, "_generate_once",
                               return_value='{"ping":"pong"}'):
            self.assertEqual(gemini_client.generate_json("s", "u"), {"ping": "pong"})

    def test_transient_then_success(self):
        calls = {"n": 0}
        def once(*a, **k):
            calls["n"] += 1
            if calls["n"] == 1:
                raise FakeExc("unavailable", 503)
            return '{"ok":1}'
        with mock.patch.object(gemini_client, "_generate_once", side_effect=once):
            self.assertEqual(gemini_client.generate_json("s", "u"), {"ok": 1})
        self.assertEqual(calls["n"], 2)

    def test_auth_not_retried(self):
        calls = {"n": 0}
        def once(*a, **k):
            calls["n"] += 1; raise FakeExc("unauthenticated", 401)
        with mock.patch.object(gemini_client, "_generate_once", side_effect=once):
            with self.assertRaises(GeminiAuthError):
                gemini_client.generate_json("s", "u")
        self.assertEqual(calls["n"], 1)  # no retry on auth

    def test_empty_then_success(self):
        seq = iter(["", '{"x":1}'])
        with mock.patch.object(gemini_client, "_generate_once",
                               side_effect=lambda *a, **k: next(seq)):
            self.assertEqual(gemini_client.generate_json("s", "u"), {"x": 1})

    def test_bad_json_raises(self):
        with mock.patch.object(gemini_client, "_generate_once", return_value="not json"):
            with self.assertRaises(GeminiResponseError):
                gemini_client.generate_json("s", "u")


class TestVerifyModel(unittest.TestCase):
    def test_supported(self):
        with mock.patch.object(gemini_client, "list_models",
                               return_value=["gemini-2.5-flash", "gemini-2.5-pro"]):
            ok, msg, _ = gemini_client.verify_model("gemini-2.5-flash")
            self.assertTrue(ok)

    def test_unsupported(self):
        with mock.patch.object(gemini_client, "list_models",
                               return_value=["gemini-2.5-pro"]):
            ok, msg, avail = gemini_client.verify_model("gemini-9-ultra")
            self.assertFalse(ok)
            self.assertIn("NOT", msg)


class TestAvailabilityAndConfig(unittest.TestCase):
    def test_no_key_not_available(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(config.get_gemini_api_key())
            self.assertFalse(gemini_client.gemini_available())

    def test_key_plus_sdk_available(self):
        with mock.patch.dict(os.environ, {"GEMINI_API_KEY": "x"}, clear=False):
            with mock.patch.object(gemini_client, "sdk_available", return_value=True):
                self.assertTrue(gemini_client.gemini_available())

    def test_summary_has_no_secret(self):
        with mock.patch.dict(os.environ, {"GEMINI_API_KEY": "super-secret-value"},
                             clear=False):
            s = config.settings_summary()
            self.assertTrue(s["gemini_key_configured"])
            self.assertNotIn("super-secret-value", str(s))


class TestProposeRuleGeminiPath(unittest.TestCase):
    def test_gemini_used_when_available(self):
        with mock.patch.object(ai.gemini_client, "gemini_available", return_value=True), \
             mock.patch.object(ai.gemini_client, "generate_json", return_value=dict(GOOD)):
            p = ai.propose_rule(SQLI, strategy="precise", use_cache=False)
            self.assertEqual(p.source, "gemini")
            self.assertEqual(p.target, "/login")

    def test_auth_failure_falls_back_to_heuristic(self):
        with mock.patch.object(ai.gemini_client, "gemini_available", return_value=True), \
             mock.patch.object(ai.gemini_client, "generate_json",
                               side_effect=GeminiAuthError("bad key")):
            p = ai.propose_rule(SQLI, strategy="precise", use_cache=False)
            self.assertEqual(p.source, "heuristic")  # never a false success

    def test_bad_candidate_then_corrective_retry(self):
        bad = {**GOOD, "target": "/evil"}   # target mismatch -> validation error
        seq = iter([bad, dict(GOOD)])
        with mock.patch.object(ai.gemini_client, "gemini_available", return_value=True), \
             mock.patch.object(ai.gemini_client, "generate_json",
                               side_effect=lambda *a, **k: next(seq)):
            p = ai.propose_rule(SQLI, strategy="precise", use_cache=False)
            self.assertEqual(p.source, "gemini")

    def test_forbidden_param_stays_deterministic(self):
        lock = Finding("F-003", "/unlock", "forbidden_param", parameter="debug")
        with mock.patch.object(ai.gemini_client, "gemini_available", return_value=True):
            p = ai.propose_rule(lock, strategy="strict", use_cache=False)
            self.assertEqual(p.source, "heuristic")  # Gemini not consulted


class TestFixesGeminiPath(unittest.TestCase):
    def test_gemini_fix_used(self):
        out = {"before": "f-string sql", "after": "parameterised ?", "explanation": "use params"}
        with mock.patch.object(fixes.gemini_client, "gemini_available", return_value=True), \
             mock.patch.object(fixes.gemini_client, "generate_json", return_value=out):
            s = fixes.suggest_fix(SQLI, "query = f\"...\"")
            self.assertEqual(s.source, "gemini")
            self.assertTrue(s.requires_review)

    def test_gemini_failure_falls_back_to_template(self):
        with mock.patch.object(fixes.gemini_client, "gemini_available", return_value=True), \
             mock.patch.object(fixes.gemini_client, "generate_json",
                               side_effect=GeminiError("down")):
            s = fixes.suggest_fix(SQLI)
            self.assertEqual(s.source, "template")


class TestSmokeTest(unittest.TestCase):
    def test_sdk_missing(self):
        with mock.patch.object(gemini_client, "sdk_available", return_value=False):
            r = gemini_client.smoke_test()
            self.assertFalse(r["passed"])
            self.assertIn("not installed", r["detail"])

    def test_happy_path(self):
        with mock.patch.object(gemini_client, "sdk_available", return_value=True), \
             mock.patch.dict(os.environ, {"GEMINI_API_KEY": "x"}, clear=False), \
             mock.patch.object(gemini_client, "verify_model",
                               return_value=(True, "ok", ["gemini-2.5-flash"])), \
             mock.patch.object(gemini_client, "generate_json", return_value={"ping": "pong"}):
            r = gemini_client.smoke_test()
            self.assertTrue(r["passed"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
