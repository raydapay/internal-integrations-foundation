import unittest
from unittest.mock import AsyncMock, patch

from fastapi import Request
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import selectinload
from sqlmodel import select

from src.app.admin import add_routing_rule
from src.domain.pf_jira.models import MappingSourceType, RoutingRule
from tests.base import BaseTest


class TestAdminRoutingRules(BaseTest):
    """Test suite for Admin UI routing rule mutations and schema parsing."""

    def setUp(self) -> None:
        """Sets up standard mock request dependencies."""
        super().setUp()
        self.mock_request = AsyncMock(spec=Request)
        self.mock_request.headers = {"HX-Request": "true"}
        self.mock_user = {"id": 1, "email": "admin@todapay.com", "role": "system_admin"}

    @patch("src.app.admin.JiraClient", autospec=True)
    @patch("src.app.admin.templates", spec=Jinja2Templates)
    async def test_add_routing_rule_parses_mapping_heuristics(
        self, mock_templates: AsyncMock, mock_jira_client_class: AsyncMock
    ) -> None:
        """Verifies HTMX form submissions correctly parse and assign MappingSourceType enums.

        Evaluates the heuristic string parsing for STATIC, PF_PAYLOAD, and TEMPLATE types.
        """
        # Form data mimicking HTMX submission with all 3 mapping heuristic patterns
        form_data = {
            "priority": "100",
            "action": "SYNC",
            "is_active": "on",
            "target_jira_project": "HR",
            "reference_issuetype": "10001",
            "mapping_summary": "Task: {{ title }}",  # Heuristic: TEMPLATE
            "mapping_assignee": "$.assigned_to.email",  # Heuristic: PF_PAYLOAD
            "mapping_labels": "PF,Onboarding",  # Heuristic: STATIC
        }
        self.mock_request.form = AsyncMock(return_value=form_data)

        # Mock Jira Client methods called at the tail end of add_routing_rule to fetch issuetype_map
        mock_jira_instance = mock_jira_client_class.return_value
        mock_jira_instance.get_issue_type_map = AsyncMock(return_value={"10001": "Task"})
        mock_jira_instance.close = AsyncMock()

        async with self.test_session_maker() as session:
            await add_routing_rule(request=self.mock_request, session=session, user=self.mock_user)

            # Fetch the newly created rule with eager loading to prevent DetachedInstanceError
            stmt = select(RoutingRule).options(selectinload(RoutingRule.field_mappings))
            rule = (await session.exec(stmt)).first()

            self.assertIsNotNone(rule)
            self.assertEqual(len(rule.field_mappings), 4)  # 3 dynamic mappings + 1 reference_issuetype injection

            # Map the results for O(1) assertion lookups
            mappings = {m.jira_field_id: m.source_type for m in rule.field_mappings}

            self.assertEqual(mappings["issuetype"], MappingSourceType.STATIC)
            self.assertEqual(mappings["summary"], MappingSourceType.TEMPLATE)
            self.assertEqual(mappings["assignee"], MappingSourceType.PF_PAYLOAD)
            self.assertEqual(mappings["labels"], MappingSourceType.STATIC)

            # Verify HTMX template response was triggered
            mock_templates.TemplateResponse.assert_called_once()
            args, _ = mock_templates.TemplateResponse.call_args
            self.assertEqual(args[0], "partials/_routing_rules_tbody.html")


if __name__ == "__main__":
    unittest.main()
