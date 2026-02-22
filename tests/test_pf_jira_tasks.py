import unittest
from unittest.mock import AsyncMock, patch

import httpx
from sqlmodel import select

from src.domain.pf_jira.models import SyncAuditLog, SyncOperation, SyncState
from src.domain.pf_jira.tasks import _compute_hash, sync_jira_to_pf_task, sync_pf_to_jira_task
from tests.base import BaseTest


class TestPfJiraTasks(BaseTest):
    """Test suite for the PeopleForce to Jira synchronization worker."""

    def test_compute_hash_determinism(self) -> None:
        """Validates that dictionary key order does not affect the resulting hash."""
        dict_a = {"id": 1, "name": "Ray", "role": "CIO"}
        dict_b = {"role": "CIO", "id": 1, "name": "Ray"}

        self.assertEqual(_compute_hash(dict_a), _compute_hash(dict_b))
        self.assertNotEqual(_compute_hash(dict_a), _compute_hash({"id": 1}))

    @patch("src.domain.pf_jira.tasks.JiraClient", autospec=True)
    @patch("src.domain.pf_jira.tasks.PeopleForceClient", autospec=True)
    async def test_sync_pf_to_jira_task_lifecycle(self, mock_pf_class, mock_jira_class) -> None:
        """Validates the create, update, and skip branches of the reconciliation engine."""
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

    @patch("src.domain.pf_jira.tasks.JiraClient", autospec=True)
    @patch("src.domain.pf_jira.tasks.PeopleForceClient", autospec=True)
    async def test_sync_pf_to_jira_task_404_recovery(self, mock_pf_class, mock_jira_class) -> None:
        """Validates that a 404 from Jira triggers local state purging (Ghost Record)."""
        task_id = "404"
        issue_key = "HR-404"
        task_dict = {"id": int(task_id), "title": "Ghost Task", "completed": False}

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


if __name__ == "__main__":
    unittest.main()
