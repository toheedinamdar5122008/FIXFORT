import unittest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from api.config import settings
from api.main import app
from api.agent37 import evaluate_sentinel_locally, review_with_agent37, _parse_sentinel_json


class TestSentinelIntegration(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_agent37_configuration_defaults(self):
        """Verifies environment variables and cost guardrails."""
        self.assertEqual(settings.agent37_instance_id, "d1r7b60za3")
        self.assertIn("d1r7b60za3.agent37.app", settings.agent37_base_url)
        self.assertGreater(settings.agent37_timeout_seconds, 0)

    def test_parse_sentinel_json(self):
        """Verifies extraction and cleaning of JSON response from Hermes agent."""
        raw_markdown = """```json
{
  "verdict": "APPROVE",
  "confidence": 0.98,
  "risk_level": "LOW",
  "analysis": "Exact pattern match for SQL injection.",
  "bypass_analysis": "No bypass detected in 5 probes.",
  "false_positive_analysis": "O'Brien and valid names pass.",
  "recommendation_summary": "Safe to deploy.",
  "permanent_fix_advice": "Use parameterized queries."
}
```"""
        parsed = _parse_sentinel_json(raw_markdown)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["verdict"], "APPROVE")
        self.assertEqual(parsed["confidence"], 0.98)

    def test_local_evaluator_passing_rule(self):
        """Verifies evaluator approves when exam passed and legitimate traffic preserved."""
        finding = {
            "id": "F-001",
            "target": "/login",
            "parameter": "username",
            "type": "sqli",
            "severity": "high",
            "description": "SQL injection in login"
        }
        rule_attempt = {
            "attempt_no": 2,
            "strategy": "precise",
            "rule_text": 'SecRule REQUEST_FILENAME "@streq /login" "id:100002,phase:2,deny,status:403"\nSecRule ARGS:username "@rx (?i)\'\\s*(or|and)\\s+[\'\\d]|--|;"',
            "syntax_ok": True,
        }
        exam_results = {
            "attacks_blocked": 5,
            "attacks_total": 5,
            "users_ok": 20,
            "users_total": 20,
            "passed": True,
            "failures": []
        }
        review = evaluate_sentinel_locally(finding, rule_attempt, exam_results)
        self.assertEqual(review["verdict"], "APPROVE")
        self.assertEqual(review["risk_level"], "LOW")
        self.assertEqual(review["instance_id"], "d1r7b60za3")
        self.assertIn("O'Brien", review["false_positive_analysis"])

    def test_local_evaluator_overbroad_rule(self):
        """Verifies evaluator recommends revision when legitimate users fail."""
        finding = {
            "id": "F-001",
            "target": "/login",
            "parameter": "username",
            "type": "sqli",
        }
        rule_attempt = {
            "attempt_no": 1,
            "strategy": "strict",
            "rule_text": 'SecRule ARGS:username "@rx \'"',
            "syntax_ok": True,
        }
        exam_results = {
            "attacks_blocked": 5,
            "attacks_total": 5,
            "users_ok": 17,
            "users_total": 20,
            "passed": False,
            "failures": [{"kind": "user", "name": "login as O'Brien", "got": 403}]
        }
        review = evaluate_sentinel_locally(finding, rule_attempt, exam_results)
        self.assertEqual(review["verdict"], "NEEDS_REVISION")
        self.assertIn("O'Brien", review["false_positive_analysis"])

    def test_sentinel_review_endpoint(self):
        """Verifies POST and GET /sentinel/review/F-001 endpoints."""
        response = self.client.post("/sentinel/review/F-001")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["finding_id"], "F-001")
        self.assertEqual(data["instance_id"], "d1r7b60za3")
        self.assertEqual(data["engine"], "agent37-hermes")
        self.assertIn(data["verdict"], ["APPROVE", "NEEDS_REVISION", "REJECT"])

        # GET should retrieve the cached review
        get_response = self.client.get("/sentinel/review/F-001")
        self.assertEqual(get_response.status_code, 200)
        self.assertEqual(get_response.json()["finding_id"], "F-001")

    def test_ready_endpoint_reports_agent37(self):
        """Verifies GET /ready endpoint surfaces agent37 status."""
        response = self.client.get("/ready")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("agent37_sentinel", data)
        self.assertEqual(data["agent37_sentinel"]["instance_id"], "d1r7b60za3")


if __name__ == "__main__":
    unittest.main()
