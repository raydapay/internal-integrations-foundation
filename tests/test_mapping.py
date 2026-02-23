import unittest

from src.domain.pf_jira.mapping import build_adf_description, evaluate_routing_rules
from src.domain.pf_jira.models import RoutingAction, RoutingRule
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
                target_jira_task_type="Bug",
            )
            # Rule 2: Medium priority (50), matches all IT domain
            rule2 = RoutingRule(
                priority=50,
                action=RoutingAction.DROP,
                condition_assignee_pattern="@it.todapay.com",
            )
            session.add_all([rule1, rule2])
            await session.commit()

            # Scenario A: Matches Rule 1 (Urgent task)
            task_a = {"title": "Urgent server restart", "assigned_to": {"email": "bob@it.todapay.com"}}
            result_a = await evaluate_routing_rules(session, task_a)

            self.assertEqual(result_a["action"], RoutingAction.SYNC)
            self.assertEqual(result_a["project"], "IT")
            self.assertEqual(result_a["task_type"], "Bug")

            # Scenario B: Matches Rule 2 (Not urgent, but in IT domain)
            task_b = {"title": "Standard maintenance", "assigned_to": {"email": "bob@it.todapay.com"}}
            result_b = await evaluate_routing_rules(session, task_b)

            self.assertEqual(result_b["action"], RoutingAction.DROP)

            # Scenario C: Matches nothing (Fallback to defaults)
            task_c = {"title": "Welcome aboard", "assigned_to": {"email": "new.hire@todapay.com"}}
            result_c = await evaluate_routing_rules(session, task_c)

            self.assertEqual(result_c["action"], RoutingAction.SYNC)
            self.assertEqual(result_c["project"], "HR")  # From settings.PF_DEFAULT_JIRA_PROJECT

    def test_build_adf_description(self) -> None:
        """Verifies the strict Atlassian Document Format (ADF) AST generation."""
        task = {
            "description_plain": "Please setup the workstation.",
            "starts_on": "2023-10-01",
            "associated_to": {"full_name": "Alice Smith"},
        }

        adf = build_adf_description(task)

        self.assertEqual(adf["type"], "doc")
        self.assertEqual(adf["version"], 1)

        # Verify custom description is injected
        self.assertEqual(adf["content"][0]["content"][0]["text"], "Please setup the workstation.")

        # Verify metadata injection
        metadata_block = adf["content"][2]["content"]
        self.assertEqual(metadata_block[1]["text"], "Subject: Alice Smith\n")
        self.assertEqual(metadata_block[2]["text"], "Deadline: 2023-10-01")


if __name__ == "__main__":
    unittest.main()
