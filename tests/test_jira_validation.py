import json
import unittest
from unittest.mock import AsyncMock, patch

from src.domain.pf_jira.models import RoutingAction, RoutingRule
from src.domain.pf_jira.tasks import validate_routing_rules_task
from tests.base import BaseTest


class TestJiraValidation(BaseTest):
    """Test suite for the proactive Jira routing validation task."""

    @patch("src.domain.pf_jira.tasks.JiraClient", autospec=True)
    async def test_validate_routing_rules_success(self, mock_jira_class) -> None:
        """Verifies validation logic when all Jira targets are valid and accessible."""
        mock_jira_instance = mock_jira_class.return_value
        # Mock Atlassian API returning valid targets
        mock_jira_instance.get_all_projects = AsyncMock(return_value=[{"key": "IT", "name": "IT Helpdesk"}])
        mock_jira_instance.get_account_id_by_email = AsyncMock(return_value="acc_123")
        mock_jira_instance.get_task_type_options = AsyncMock(return_value=["Task", "Bug"])
        mock_jira_instance.close = AsyncMock()

        # Seed the DB with a rule matching the mocked valid targets
        async with self.test_session_maker() as session:
            rule = RoutingRule(
                priority=10,
                action=RoutingAction.SYNC,
                target_jira_project="IT",
                target_jira_task_type="Bug",
                target_assignee_email="admin@todapay.com",
            )
            session.add(rule)
            await session.commit()

        # Execute the validation background task
        report = await validate_routing_rules_task(self.ctx)

        # Assertions
        self.assertEqual(report["status"], "completed")
        self.assertEqual(len(report["details"]), 3)
        self.assertTrue(all(d["valid"] for d in report["details"]), "Expected all targets to validate successfully.")

        # Verify the report was cached in Redis for HTMX to pick up
        self.ctx["redis"].setex.assert_awaited_once()
        args, _ = self.ctx["redis"].setex.call_args
        self.assertEqual(args[0], "pf_jira:validation_report")
        self.assertEqual(args[1], 300)

        cached_data = json.loads(args[2])
        self.assertEqual(cached_data["status"], "completed")

    @patch("src.domain.pf_jira.tasks.JiraClient", autospec=True)
    async def test_validate_routing_rules_failures(self, mock_jira_class) -> None:
        """Verifies validation correctly identifies missing permissions and invalid types."""
        mock_jira_instance = mock_jira_class.return_value
        # Mock Atlassian API returning different targets
        mock_jira_instance.get_all_projects = AsyncMock(return_value=[{"key": "HR", "name": "Human Resources"}])
        mock_jira_instance.get_account_id_by_email = AsyncMock(return_value=None)  # Simulates user not found
        mock_jira_instance.get_task_type_options = AsyncMock(return_value=["Task"])
        mock_jira_instance.close = AsyncMock()

        # Seed the DB with a rule containing invalid targets
        async with self.test_session_maker() as session:
            rule = RoutingRule(
                priority=20,
                action=RoutingAction.SYNC,
                target_jira_project="SEC",  # Not in mock project list
                target_jira_task_type="Epic",  # Not in mock task types
                target_assignee_email="ghost@todapay.com",  # Unresolvable email
            )
            session.add(rule)
            await session.commit()

        # Execute the validation background task
        report = await validate_routing_rules_task(self.ctx)

        # Assertions
        self.assertEqual(report["status"], "completed")
        self.assertEqual(len(report["details"]), 3)
        self.assertFalse(any(d["valid"] for d in report["details"]), "Expected all targets to fail validation.")

    @patch("src.domain.pf_jira.tasks.JiraClient", autospec=True)
    async def test_validate_routing_rules_exception_handling(self, mock_jira_class) -> None:
        """Verifies the task gracefully fails and updates Redis on catastrophic error."""
        mock_jira_instance = mock_jira_class.return_value
        # Force a specific runtime exception
        mock_jira_instance.get_all_projects.side_effect = RuntimeError("Atlassian API Outage")
        mock_jira_instance.close = AsyncMock()

        # Assert the exact exception type to satisfy ruff strictness
        with self.assertRaises(RuntimeError):
            await validate_routing_rules_task(self.ctx)

        # Verify the failure state was written to Redis
        self.ctx["redis"].setex.assert_awaited_once()
        args, _ = self.ctx["redis"].setex.call_args

        cached_data = json.loads(args[2])
        self.assertEqual(cached_data["status"], "failed")
        self.assertIn("Atlassian API Outage", cached_data["error"])


if __name__ == "__main__":
    unittest.main()
