import json
from unittest.mock import AsyncMock, patch

from src.domain.pf_jira.models import MappingSourceType, RoutingAction, RoutingRule, RuleFieldMapping
from src.domain.pf_jira.tasks import validate_routing_rules_task
from tests.base import BaseTest


class TestJiraValidation(BaseTest):
    """Test suite for the proactive Jira routing validation task."""

    @patch("src.domain.pf_jira.tasks.FieldDataResolver", autospec=True)
    @patch("src.domain.pf_jira.tasks.JiraClient", autospec=True)
    async def test_validate_routing_rules_success(self, mock_jira_class, mock_resolver_class) -> None:
        """Verifies validation logic when all Jira targets are valid and accessible."""
        mock_resolver_instance = mock_resolver_class.return_value
        # Mock valid live schema returned by Jira
        mock_resolver_instance._get_createmeta = AsyncMock(
            return_value={"customfield_100": {"required": False, "name": "Optional Field"}}
        )

        async with self.test_session_maker() as session:
            rule1 = RoutingRule(
                priority=10,
                action=RoutingAction.SYNC,
                target_jira_project="IT",
                is_active=True,
                field_mappings=[
                    RuleFieldMapping(
                        jira_field_id="issuetype", source_type=MappingSourceType.STATIC, source_value="10001"
                    )
                ],
            )
            rule2 = RoutingRule(
                priority=20,
                action=RoutingAction.SYNC,
                target_jira_project="HR",
                is_active=True,
                field_mappings=[
                    RuleFieldMapping(
                        jira_field_id="issuetype", source_type=MappingSourceType.STATIC, source_value="10002"
                    )
                ],
            )
            rule3 = RoutingRule(
                priority=30,
                action=RoutingAction.SYNC,
                target_jira_project="FIN",
                is_active=True,
                field_mappings=[
                    RuleFieldMapping(
                        jira_field_id="issuetype", source_type=MappingSourceType.STATIC, source_value="10003"
                    )
                ],
            )
            session.add_all([rule1, rule2, rule3])
            await session.commit()

        report = await validate_routing_rules_task(self.ctx)

        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["validated"], 3)
        self.assertEqual(len(report["details"]), 3)

    @patch("src.domain.pf_jira.tasks.FieldDataResolver", autospec=True)
    @patch("src.domain.pf_jira.tasks.JiraClient", autospec=True)
    async def test_validate_routing_rules_failures(self, mock_jira_class, mock_resolver_class) -> None:
        """Verifies validation catches schema drift and disables the rule."""
        mock_resolver_instance = mock_resolver_class.return_value
        # Mock drift: Jira now requires a field we haven't mapped
        mock_resolver_instance._get_createmeta = AsyncMock(
            return_value={"customfield_666": {"required": True, "name": "Strict Compliance Field"}}
        )

        async with self.test_session_maker() as session:
            rule1 = RoutingRule(
                priority=10,
                action=RoutingAction.SYNC,
                target_jira_project="IT",
                is_active=True,
                field_mappings=[
                    RuleFieldMapping(
                        jira_field_id="issuetype", source_type=MappingSourceType.STATIC, source_value="10001"
                    )
                ],
            )
            session.add(rule1)
            await session.commit()

        report = await validate_routing_rules_task(self.ctx)

        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["disabled"], 1)
        self.assertFalse(report["details"][0]["valid"])

    @patch("src.domain.pf_jira.tasks.FieldDataResolver", autospec=True)
    @patch("src.domain.pf_jira.tasks.JiraClient", autospec=True)
    async def test_validate_routing_rules_exception_handling(self, mock_jira_class, mock_resolver_class) -> None:
        """Verifies the task gracefully fails and updates Redis on catastrophic error."""
        mock_resolver_instance = mock_resolver_class.return_value
        mock_resolver_instance._get_createmeta.side_effect = RuntimeError("Atlassian API Outage")

        async with self.test_session_maker() as session:
            rule1 = RoutingRule(
                priority=10,
                action=RoutingAction.SYNC,
                target_jira_project="IT",
                is_active=True,
                field_mappings=[
                    RuleFieldMapping(
                        jira_field_id="issuetype", source_type=MappingSourceType.STATIC, source_value="10001"
                    )
                ],
            )
            session.add(rule1)
            await session.commit()

        with self.assertRaises(RuntimeError):
            await validate_routing_rules_task(self.ctx)

        self.ctx["redis"].setex.assert_awaited_once()
        args, _ = self.ctx["redis"].setex.call_args
        self.assertEqual(json.loads(args[2])["status"], "failed")
