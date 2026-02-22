import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine

from src.app.main import app


class TestPfJiraRouter(unittest.IsolatedAsyncioTestCase):
    """Test suite for the PeopleForce-Jira API Gateway routing."""

    def setUp(self) -> None:
        """Injects a mocked ARQ pool and intercepts the database lifespan."""
        # 1. Prevent FastAPI Lifespan from touching the physical DB
        self.test_engine = create_async_engine("sqlite+aiosqlite://")
        self.engine_patcher = patch("src.app.main.engine", self.test_engine)
        self.engine_patcher.start()

        # 2. Mock the ARQ Queue
        self.mock_pool = AsyncMock()
        mock_job = MagicMock()
        mock_job.job_id = "test_enqueue_id_123"
        self.mock_pool.enqueue_job.return_value = mock_job

        # Override the app state before initializing the TestClient
        app.state.arq_pool = self.mock_pool
        self.client = TestClient(app)

    def tearDown(self) -> None:
        self.engine_patcher.stop()

    def test_trigger_sync_enqueues_isolated_job(self) -> None:
        """Validates that a valid payload is routed to the correct ARQ queue."""
        payload = {"email": "ray@example.com"}

        response = self.client.post("/api/v1/pf-jira/sync", json=payload)

        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()["job_id"], "test_enqueue_id_123")

        # Ensure the gateway enforces the correct isolated queue boundary
        self.mock_pool.enqueue_job.assert_called_once_with(
            "sync_pf_to_jira_task", {"email": "ray@example.com", "manual_trigger": False}, _queue_name="pf_jira_queue"
        )

    def test_trigger_sync_handles_missing_arq_pool(self) -> None:
        """Validates 500 error handling when the Redis pool is unavailable."""
        app.state.arq_pool = None

        response = self.client.post("/api/v1/pf-jira/sync", json={})

        self.assertEqual(response.status_code, 500)
        self.assertIn("ARQ Redis pool not initialized", response.json()["detail"])


if __name__ == "__main__":
    unittest.main()
