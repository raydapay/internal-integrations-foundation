import hashlib
import hmac
import json
import unittest
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine

from src.app.main import app


class TestJiraWebhookIngress(unittest.IsolatedAsyncioTestCase):
    """Test suite for Atlassian webhook cryptographic validation and routing."""

    def setUp(self) -> None:
        """Initializes the test client, intercepts the DB, and mocks ARQ."""
        # Prevent FastAPI Lifespan from touching the physical DB
        self.test_engine = create_async_engine("sqlite+aiosqlite://")
        self.engine_patcher = patch("src.app.main.engine", self.test_engine)
        self.engine_patcher.start()

        self.mock_pool = AsyncMock()
        app.state.arq_pool = self.mock_pool
        self.client = TestClient(app)

        self.secret = "test_cryptographic_secret_key_123"
        self.payload_dict = {
            "webhookEvent": "jira:issue_updated",
            "issue": {"key": "HR-123", "fields": {"status": {"statusCategory": {"key": "done"}}}},
        }
        # Dump with no spaces to strictly control byte output for constant-time comparison
        self.raw_payload = json.dumps(self.payload_dict, separators=(",", ":")).encode("utf-8")

    def tearDown(self) -> None:
        self.engine_patcher.stop()

    def _generate_signature(self, secret: str, payload: bytes) -> str:
        """Generates a valid Atlassian HMAC-SHA256 signature."""
        mac = hmac.new(secret.encode("utf-8"), msg=payload, digestmod=hashlib.sha256)
        return f"sha256={mac.hexdigest()}"

    @patch("src.core.security.settings")
    def test_valid_signature_enqueues_job(self, mock_settings: AsyncMock) -> None:
        """Verifies that a mathematically valid signature results in an enqueued ARQ job."""
        mock_settings.JIRA_WEBHOOK_SECRET = self.secret
        headers = {"X-Hub-Signature": self._generate_signature(self.secret, self.raw_payload)}

        response = self.client.post("/api/v1/webhooks/jira", content=self.raw_payload, headers=headers)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "accepted"})
        self.mock_pool.enqueue_job.assert_called_once_with(
            "sync_jira_to_pf_task", "HR-123", _queue_name="pf_jira_queue"
        )

    @patch("src.core.security.settings")
    def test_invalid_signature_rejected(self, mock_settings: AsyncMock) -> None:
        """Verifies that payload spoofing attempts are rejected with HTTP 403."""
        mock_settings.JIRA_WEBHOOK_SECRET = self.secret

        # Calculate signature against a different secret to simulate an attack
        forged_signature = self._generate_signature("wrong_secret_key", self.raw_payload)
        headers = {"X-Hub-Signature": forged_signature}

        response = self.client.post("/api/v1/webhooks/jira", content=self.raw_payload, headers=headers)

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["detail"], "Signature mismatch.")
        self.mock_pool.enqueue_job.assert_not_called()

    @patch("src.core.security.settings")
    def test_missing_signature_header(self, mock_settings: AsyncMock) -> None:
        """Verifies that requests omitting the security header are rejected immediately."""
        mock_settings.JIRA_WEBHOOK_SECRET = self.secret

        response = self.client.post("/api/v1/webhooks/jira", content=self.raw_payload)

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["detail"], "Missing signature.")

    @patch("src.core.security.settings")
    def test_unconfigured_environment_fails_closed(self, mock_settings: AsyncMock) -> None:
        """Verifies the system fails closed (HTTP 500) if the webhook secret is missing."""
        mock_settings.JIRA_WEBHOOK_SECRET = None
        headers = {"X-Hub-Signature": "sha256=dummyhash"}

        response = self.client.post("/api/v1/webhooks/jira", content=self.raw_payload, headers=headers)

        self.assertEqual(response.status_code, 500)
        self.assertIn("Configuration missing", response.json()["detail"])

    @patch("src.core.security.settings")
    def test_irrelevant_webhook_event_ignored(self, mock_settings: AsyncMock) -> None:
        """Verifies that non-completion events are acknowledged but not enqueued."""
        mock_settings.JIRA_WEBHOOK_SECRET = self.secret

        # Mutate payload to a non-terminal event
        irrelevant_payload = dict(self.payload_dict)
        irrelevant_payload["webhookEvent"] = "jira:issue_updated"
        irrelevant_payload["issue"]["fields"]["status"]["statusCategory"]["key"] = "in_progress"

        raw_irrelevant = json.dumps(irrelevant_payload, separators=(",", ":")).encode("utf-8")
        headers = {"X-Hub-Signature": self._generate_signature(self.secret, raw_irrelevant)}

        response = self.client.post("/api/v1/webhooks/jira", content=raw_irrelevant, headers=headers)

        self.assertEqual(response.status_code, 200)
        # ARQ worker should not be triggered for non-terminal states
        self.mock_pool.enqueue_job.assert_not_called()

    @patch("src.core.security.settings")
    def test_jira_webhook_arq_pool_missing_returns_500(self, mock_settings: AsyncMock) -> None:
        """Verifies the webhook endpoint fails closed if the ARQ pool is detached from app state."""
        mock_settings.JIRA_WEBHOOK_SECRET = self.secret
        headers = {"X-Hub-Signature": self._generate_signature(self.secret, self.raw_payload)}

        original_pool = getattr(self.client.app.state, "arq_pool", None)
        self.client.app.state.arq_pool = None

        try:
            response = self.client.post("/api/v1/webhooks/jira", content=self.raw_payload, headers=headers)
            self.assertEqual(response.status_code, 500)
            self.assertIn("Queue unavailable", response.json()["detail"])
        finally:
            self.client.app.state.arq_pool = original_pool

    @patch("src.core.security.settings")
    def test_jira_webhook_enqueue_failure_returns_500(self, mock_settings: AsyncMock) -> None:
        """Verifies the webhook endpoint handles broker rejection and prevents silent drops."""
        mock_settings.JIRA_WEBHOOK_SECRET = self.secret
        headers = {"X-Hub-Signature": self._generate_signature(self.secret, self.raw_payload)}

        original_pool = getattr(self.client.app.state, "arq_pool", None)
        mock_pool = AsyncMock()
        mock_pool.enqueue_job.return_value = None
        self.client.app.state.arq_pool = mock_pool

        try:
            response = self.client.post("/api/v1/webhooks/jira", content=self.raw_payload, headers=headers)
            self.assertEqual(response.status_code, 500)
            self.assertIn("Failed to enqueue", response.json()["detail"])
        finally:
            self.client.app.state.arq_pool = original_pool


if __name__ == "__main__":
    unittest.main()
