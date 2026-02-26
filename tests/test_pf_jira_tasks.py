import unittest
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
from arq.worker import Retry
from sqlalchemy.exc import OperationalError
from sqlmodel import select

from src.domain.pf_jira.models import RoutingAction, SyncAuditLog, SyncOperation, SyncState
from src.domain.pf_jira.tasks import _compute_hash, sync_jira_to_pf_task, sync_pf_to_jira_task, zombie_recovery_task
from tests.base import BaseTest


class TestPfJiraTasks(BaseTest):
    """Test suite for the PeopleForce to Jira synchronization worker."""

    def test_compute_hash_determinism(self) -> None:
        """Validates that dictionary key order does not affect the resulting hash."""
        dict_a = {"id": 1, "name": "Ray", "role": "CIO"}
        dict_b = {"role": "CIO", "id": 1, "name": "Ray"}

        self.assertEqual(_compute_hash(dict_a), _compute_hash(dict_b))
        self.assertNotEqual(_compute_hash(dict_a), _compute_hash({"id": 1}))

    @patch("src.domain.pf_jira.tasks.evaluate_routing_rules")
    @patch("src.domain.pf_jira.tasks.JiraClient", autospec=True)
    @patch("src.domain.pf_jira.tasks.PeopleForceClient", autospec=True)
    async def test_sync_pf_to_jira_task_lifecycle(self, mock_pf_class, mock_jira_class, mock_evaluate) -> None:
        """Validates the create, update, and skip branches of the reconciliation engine."""
        # Mock the routing engine to always return SYNC and a dummy payload
        mock_evaluate.return_value = (RoutingAction.SYNC, {"fields": {"project": {"key": "IT"}}})
        task_1 = {
            "id": 100,
            "title": "Onboarding",
            "completed": False,
            "assigned_to": {"email": "john@example.com"},
            "associated_to": {"full_name": "John Doe"},
        }
        task_2 = {
            "id": 200,
            "title": "Offboarding",
            "completed": False,
            "assigned_to": {"email": "jane@example.com"},
            "associated_to": {"full_name": "Jane Doe"},
        }

        # Strict async side effects to bypass AsyncMock ambiguity
        async def fake_get_tasks(*args, **kwargs):
            return [task_1, task_2]

        mock_pf_instance = mock_pf_class.return_value
        mock_pf_instance.get_tasks.side_effect = fake_get_tasks
        mock_pf_instance.close = AsyncMock()

        mock_jira_instance = mock_jira_class.return_value
        mock_jira_instance.create_issue = AsyncMock(
            side_effect=[
                {"id": "10001", "key": "HR-1"},
                {"id": "10002", "key": "HR-2"},
            ]
        )
        mock_jira_instance.update_issue = AsyncMock()
        mock_jira_instance.transition_issue_to_done = AsyncMock()
        mock_jira_instance.add_comment = AsyncMock()
        mock_jira_instance.get_account_id_by_email = AsyncMock(return_value="jira_account_123")
        mock_jira_instance.close = AsyncMock()

        # --- RUN 1: Initial Sync (Creates 2) ---
        stats_1 = await sync_pf_to_jira_task(self.ctx)
        self.assertEqual(stats_1["created"], 2)
        self.assertEqual(stats_1["skipped"], 0)
        self.assertEqual(mock_jira_instance.create_issue.call_count, 2)

        # --- RUN 2: Unchanged Sync (Skips 2) ---
        mock_jira_instance.create_issue.reset_mock()
        stats_2 = await sync_pf_to_jira_task(self.ctx)
        self.assertEqual(stats_2["created"], 0)
        self.assertEqual(stats_2["skipped"], 2)
        mock_jira_instance.create_issue.assert_not_called()

        # --- RUN 3: Mutated Sync (Updates 1, Skips 1) ---
        task_1_mutated = dict(task_1)
        task_1_mutated["title"] = "Onboarding - Updated"

        async def fake_get_tasks_mutated(*args, **kwargs):
            return [task_1_mutated, task_2]

        mock_pf_instance.get_tasks.side_effect = fake_get_tasks_mutated

        stats_3 = await sync_pf_to_jira_task(self.ctx)
        self.assertEqual(stats_3["updated"], 1)
        self.assertEqual(stats_3["skipped"], 1)
        mock_jira_instance.update_issue.assert_awaited_once()

    @patch("src.domain.pf_jira.tasks.evaluate_routing_rules")
    @patch("src.domain.pf_jira.tasks.JiraClient")
    @patch("src.domain.pf_jira.tasks.PeopleForceClient", autospec=True)
    async def test_sync_pf_to_jira_task_404_recovery(self, mock_pf_class, mock_jira_class, mock_evaluate) -> None:
        """Validates that a 404 from Jira triggers local state purging (Ghost Record)."""

        # Create a fake 404 HTTPStatusError to trigger the Ghost Record recovery
        def fake_put(*args, **kwargs):
            mock_resp = MagicMock()
            mock_resp.status_code = 404
            raise httpx.HTTPStatusError("404 Not Found", request=MagicMock(), response=mock_resp)

        mock_jira_instance = mock_jira_class.return_value
        # Apply the mock to the raw HTTPX client's PUT method instead of 'update_issue'
        mock_jira_instance.client.put.side_effect = fake_put

        task_id = "404"
        issue_key = "HR-404"
        task_dict = {"id": int(task_id), "title": "Ghost Task", "completed": False}

        # Mock the routing engine to always return SYNC and a dummy payload
        mock_evaluate.return_value = (RoutingAction.SYNC, {"fields": {"project": {"key": "HR"}}})

        async def fake_get_tasks(*args, **kwargs):
            return [task_dict]

        mock_pf_instance = mock_pf_class.return_value
        mock_pf_instance.get_tasks.side_effect = fake_get_tasks
        mock_pf_instance.close = AsyncMock()

        request = httpx.Request("PUT", f"https://api.atlassian.com/.../{issue_key}")
        response = httpx.Response(404, request=request)

        async def fake_update_issue(*args, **kwargs):
            raise httpx.HTTPStatusError("404 Not Found", request=request, response=response)

        mock_jira_instance = mock_jira_class.return_value
        mock_jira_instance.update_issue.side_effect = fake_update_issue
        mock_jira_instance.get_account_id_by_email = AsyncMock(return_value="jira_account_123")
        mock_jira_instance.close = AsyncMock()

        # 1. Seed existing database state
        initial_hash = _compute_hash(task_dict)
        async with self.test_session_maker() as session:
            state = SyncState(
                pf_entity_type="task",
                pf_entity_id=task_id,
                jira_issue_key=issue_key,
                jira_issue_id="99999",
                last_sync_hash=initial_hash,
                is_completed=False,
            )
            session.add(state)
            await session.commit()

        # 2. Mutate the payload to force the update block
        task_dict["title"] = "Ghost Task - Mutated"

        # 3. Execute the worker
        stats = await sync_pf_to_jira_task(self.ctx)

        # 4. Verify the self-healing actions
        self.assertEqual(stats["updated"], 0)

        async with self.test_session_maker() as session:
            purged_state = (await session.exec(select(SyncState).where(SyncState.jira_issue_key == issue_key))).first()
            self.assertIsNone(purged_state)

            audit_log = (
                await session.exec(select(SyncAuditLog).where(SyncAuditLog.operation == SyncOperation.ERROR))
            ).first()
            self.assertIsNotNone(audit_log)
            self.assertIn("Jira 404 Not Found", audit_log.details)

    @patch("src.domain.pf_jira.tasks.evaluate_routing_rules")
    @patch("src.domain.pf_jira.tasks.JiraClient", autospec=True)
    @patch("src.domain.pf_jira.tasks.PeopleForceClient", autospec=True)
    async def test_cache_invalidation_on_jira_400(self, mock_pf_class, mock_jira_class, mock_evaluate) -> None:
        """Verifies HTTP 400 Bad Request triggers targeted Redis schema cache purge.

        Simulates a schema drift scenario where the local cache is stale and Jira
        rejects the payload. The engine must trap the 400, purge the exact project/issuetype
        createmeta cache key, and raise a Retry to force a fresh pre-flight check.
        """
        # 1. Setup payload with explicit project and issuetype vectors
        payload = {"fields": {"project": {"key": "IT"}, "issuetype": {"id": "10010"}, "summary": "Stale Schema Test"}}
        mock_evaluate.return_value = (RoutingAction.SYNC, payload)

        # 2. Fake the HTTP 400 Bad Request from Atlassian during issue creation
        def fake_create_issue(*args, **kwargs):
            mock_resp = MagicMock()
            mock_resp.status_code = 400
            raise httpx.HTTPStatusError("400 Bad Request", request=MagicMock(), response=mock_resp)

        mock_jira_instance = mock_jira_class.return_value
        mock_jira_instance.create_issue.side_effect = fake_create_issue
        mock_jira_instance.get_account_id_by_email = AsyncMock(return_value="acc_123")
        mock_jira_instance.close = AsyncMock()

        # 3. Supply a dummy task to trigger the loop
        task_dict = {"id": 999, "title": "Trigger Task", "completed": False}

        async def fake_get_tasks(*args, **kwargs):
            return [task_dict]

        mock_pf_instance = mock_pf_class.return_value
        mock_pf_instance.get_tasks.side_effect = fake_get_tasks
        mock_pf_instance.close = AsyncMock()

        # 4. Execute the worker and trap the expected ARQ Retry
        with self.assertRaises(Retry) as context:
            await sync_pf_to_jira_task(self.ctx)

        # Assert a 5-second backoff was applied to allow cache invalidation
        self.assertIn("5", str(context.exception))

        # 5. Assert targeted cache invalidation occurred mapped exactly to resolver.py format
        self.mock_redis.delete.assert_awaited_once_with("jira:createmeta:IT:10010")

    @patch("src.domain.pf_jira.tasks.PeopleForceClient", autospec=True)
    async def test_sync_jira_to_pf_task_success(self, mock_pf_class) -> None:
        """Validates successful Jira-to-PF task resolution and completion execution."""
        mock_pf_instance = mock_pf_class.return_value
        mock_pf_instance.complete_task = AsyncMock()
        mock_pf_instance.close = AsyncMock()

        # Seed Database
        async with self.test_session_maker() as session:
            state = SyncState(
                pf_entity_type="task",
                pf_entity_id="999",
                jira_issue_key="HR-999",
                jira_issue_id="10999",
                last_sync_hash="testhash",
                is_completed=False,
            )
            session.add(state)
            await session.commit()

        # Execute Worker Task
        await sync_jira_to_pf_task(self.ctx, "HR-999")

        # Verify Execution
        mock_pf_instance.complete_task.assert_awaited_once_with("999")

        # Verify DB State Mutation
        async with self.test_session_maker() as session:
            updated_state = (await session.exec(select(SyncState).where(SyncState.jira_issue_key == "HR-999"))).first()
            self.assertTrue(updated_state.is_completed)

            audit_log = (
                await session.exec(select(SyncAuditLog).where(SyncAuditLog.jira_issue_key == "HR-999"))
            ).first()
            self.assertIsNotNone(audit_log)
            self.assertEqual(audit_log.direction, "Jira ➡️ PF")

    @patch("src.domain.pf_jira.tasks.notify")
    @patch("src.domain.pf_jira.tasks.logger")
    @patch("src.domain.pf_jira.tasks._process_single_task")
    async def test_sync_pf_to_jira_task_wal_lock_contention(
        self, mock_process_single_task: AsyncMock, mock_logger: MagicMock, mock_notify: AsyncMock
    ) -> None:
        """Verifies SQLite WAL concurrency constraints trigger ARQ task backoff.

        Simulates a 'database is locked' OperationalError raised by SQLAlchemy when
        another ARQ worker holds the SQLite write lock beyond the timeout threshold.

        Args:
            mock_process_single_task: Mocked internal processing to inject the DB exception.
            mock_logger: Suppresses stdout exception tracebacks during the simulated crash.
            mock_notify: Intercepts the Slack/Telegram alert dispatch.
        """
        # Simulate SQLite WAL lock contention
        sqlite_error = OperationalError("statement", "params", orig=Exception("database is locked"))
        mock_process_single_task.side_effect = sqlite_error

        # We expect the worker to catch OperationalError and explicitly raise an arq.worker.Retry
        with self.assertRaises(Retry) as context:
            await sync_pf_to_jira_task(self.ctx)

        # ARQ's Retry object representation contains the defer time (e.g., '<Retry defer 5.00s>')
        self.assertIn("5", str(context.exception))

        # Verify the system attempted to dispatch the catastrophic failure alert
        mock_notify.assert_awaited_once()

    @patch("src.domain.pf_jira.tasks.logger")
    @patch("src.domain.pf_jira.tasks.JiraClient")
    async def test_sync_jira_to_pf_task_wal_lock_contention(
        self, mock_jira_class: AsyncMock, mock_logger: MagicMock
    ) -> None:
        """Verifies database lock contention handling on the reverse sync vector.

        Args:
            mock_jira_class: Mocked client to bypass external Atlassian calls.
            mock_logger: Suppresses stdout exception tracebacks during the simulated crash.
        """
        # 1. Setup the session mock to raise the exception
        mock_session = AsyncMock()
        mock_session.exec.side_effect = OperationalError("statement", "params", orig=Exception("database is locked"))

        # 2. Properly construct an async context manager for the session maker override
        @asynccontextmanager
        async def mock_maker():
            yield mock_session

        # 3. Inject the context manager and execute
        with patch("src.domain.pf_jira.tasks.async_session_maker", return_value=mock_maker()):
            with self.assertRaises(Retry) as context:
                await sync_jira_to_pf_task(self.ctx, "HR-999")

            self.assertIn("5", str(context.exception))

    @patch("src.domain.pf_jira.tasks.JiraClient", autospec=True)
    @patch("src.domain.pf_jira.tasks.sync_jira_to_pf_task")
    async def test_zombie_recovery_task_delegation(self, mock_sync_task: AsyncMock, mock_jira_class) -> None:
        """Validates the JQL sweeper correctly identifies and delegates orphaned tasks."""
        mock_jira_instance = mock_jira_class.return_value
        mock_jira_instance.search_issues = AsyncMock(return_value=[{"key": "HR-1"}, {"key": "HR-2"}, {"key": "HR-3"}])
        mock_jira_instance.close = AsyncMock()

        # Seed DB: HR-1 is unresolved, HR-2 is already resolved, HR-3 doesn't exist locally.
        async with self.test_session_maker() as session:
            state_1 = SyncState(
                pf_entity_type="task",
                pf_entity_id="1",
                jira_issue_key="HR-1",
                jira_issue_id="101",
                last_sync_hash="hash",
                is_completed=False,
            )
            state_2 = SyncState(
                pf_entity_type="task",
                pf_entity_id="2",
                jira_issue_key="HR-2",
                jira_issue_id="102",
                last_sync_hash="hash",
                is_completed=True,
            )
            session.add_all([state_1, state_2])
            await session.commit()

        stats = await zombie_recovery_task(self.ctx)

        self.assertEqual(stats["found"], 3)
        self.assertEqual(stats["recovered"], 1)  # Only HR-1 should trigger recovery delegation
        self.assertEqual(stats["errors"], 0)

        mock_sync_task.assert_awaited_once_with(self.ctx, "HR-1")

        # Verify the explicit JQL target
        args, _ = mock_jira_instance.search_issues.call_args
        self.assertIn("labels = PeopleForce", args[0])
        self.assertIn("-24h", args[0])


if __name__ == "__main__":
    unittest.main()
