import sys
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from main import app
from firebase_db import sanitize_url
import os


class PublicEndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_health_endpoint_reports_active_service(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "active")

    def test_stats_endpoint_does_not_claim_fabricated_metrics(self):
        response = self.client.get("/stats")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertIsNone(body["total_scans"])
        self.assertIsNone(body["threats_blocked"])
        self.assertFalse(body["stats_available"])
        self.assertEqual(body["model_version"], "legacy-xgboost")

    def test_sanitize_url_fallback(self):
        # Normal
        self.assertEqual(sanitize_url("https://example.com/path?query=1"), "https://example.com/path")
        self.assertEqual(sanitize_url("https://user:pass@example.com/path"), "https://example.com/path")

        # We can simulate an exception by passing None (which will crash urlparse)
        self.assertEqual(sanitize_url(None), "https://invalid-url-sanitization-failed")

    def test_cors_credentials_are_disabled(self):
        # We enforce allow_credentials=False so that the wildcard origin isn't a massive CSRF hole
        response = self.client.options(
            "/analyze",
            headers={
                "Origin": "https://attacker.com",
                "Access-Control-Request-Method": "POST"
            }
        )
        self.assertEqual(response.status_code, 200)
        # Should not have allow-credentials true
        self.assertNotIn("access-control-allow-credentials", response.headers)

    def test_admin_route_requires_auth(self):
        # Without auth
        response = self.client.get("/admin/reports")
        self.assertEqual(response.status_code, 401)

        # With incorrect auth
        response = self.client.get("/admin/reports", auth=("admin", "wrongpassword"))
        self.assertEqual(response.status_code, 401)

        # We can't easily test correct auth without knowing the env var, but testing 401 is sufficient
        # to prove it's not publicly exposed.


if __name__ == "__main__":
    unittest.main()
