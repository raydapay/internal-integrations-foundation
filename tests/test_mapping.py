from unittest.mock import AsyncMock

from src.domain.pf_jira.mapping import evaluate_routing_rules
from src.domain.pf_jira.models import MappingSourceType, RoutingAction, RoutingRule, RuleFieldMapping
from tests.base import BaseTest


class TestMappingEngine(BaseTest):
    """Test suite for the Firewall-style Routing Engine and payload generation."""

    async def test_evaluate_routing_rules_linear_priority(self) -> None:
        """Verifies rules are evaluated in priority order and stop on the first match."""
        async with self.test_session_maker() as session:
            # Rule 1: High priority (10), matches specific title
            rule1 = RoutingRule(
                priority=10,
                action=RoutingAction.SYNC,
                condition_title_keyword="urgent",
                target_jira_project="IT",
                field_mappings=[
                    RuleFieldMapping(
                        jira_field_id="issuetype", source_type=MappingSourceType.STATIC, source_value="10001"
                    )
                ],
            )
            # Rule 2: Medium priority (50), matches all IT domain
            rule2 = RoutingRule(
                priority=50,
                action=RoutingAction.DROP,
                condition_assignee_pattern="@it.todapay.com",
            )
            session.add_all([rule1, rule2])
            await session.commit()

            # Mock the resolver output
            mock_resolver = AsyncMock()
            mock_resolver.build_payload.return_value = {
                "fields": {"project": {"key": "IT"}, "issuetype": {"id": "10001"}}
            }

            # Scenario A: Matches Rule 1 (Urgent task)
            task_a = {"title": "Urgent server restart", "assigned_to": {"email": "bob@it.todapay.com"}}
            action_a, _ = await evaluate_routing_rules(session, task_a, mock_resolver)
            self.assertEqual(action_a, RoutingAction.SYNC)

            # Scenario B: Matches Rule 2 (IT domain)
            task_b = {"title": "Fix printer", "assigned_to": {"email": "bob@it.todapay.com"}}
            action_b, _ = await evaluate_routing_rules(session, task_b, mock_resolver)
            self.assertEqual(action_b, RoutingAction.DROP)

            # Scenario C: Matches nothing (Fallback to defaults)
            task_c = {"title": "Welcome aboard", "assigned_to": {"email": "new.hire@todapay.com"}}
            action_c, _ = await evaluate_routing_rules(session, task_c, mock_resolver)
            self.assertEqual(action_c, RoutingAction.DROP)
