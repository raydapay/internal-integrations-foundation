import unittest
from typing import Any
from unittest.mock import MagicMock, patch

from src.app.admin import audit_dashboard
from src.domain.pf_jira.models import SyncAuditLog, SyncOperation
from src.domain.pf_jira.tasks import _extract_pf_search_context
from tests.base import BaseTest


class MockAuditParams:
    """Mock implementation of the FastAPI Depends() query params for the audit route."""

    def __init__(self, page: int = 1, query: str | None = None, operation: SyncOperation | None = None) -> None:
        self.page = page
        self.query = query
        self.operation = operation


class TestAuditSearchAndContext(BaseTest):
    """Test suite for the targeted state-extraction and real database search logic."""

    def test_extract_pf_search_context_full_payload(self) -> None:
        """Verifies correct concatenation of ID, title, and assignee metadata."""
        payload: dict[str, Any] = {
            "id": 3199153,
            "title": "1:1 Review",
            "description": "Discuss <b>achievements</b> and salary.",
            "description_plain": "Discuss achievements and salary.",
            "associated_to": {
                "id": 101699,
                "type": "Employee",
                "full_name": "FirstNameY LastNameY",
                "email": "yyy@example.com",
            },
            "assigned_to": {"id": 273297, "full_name": "FirstNameX LastNameX", "email": "xxx@example.com"},
            "completed": False,
            "irrelevant_data": "Should be ignored",
        }

        result = _extract_pf_search_context(payload)

        expected_vector = (
            "3199153 | 1:1 Review | Discuss achievements and salary. | yyy@example.com | "
            "FirstNameY LastNameY | xxx@example.com | FirstNameX LastNameX"
        )
        self.assertEqual(result, expected_vector)
        self.assertNotIn("False", result)
        self.assertNotIn("Should be ignored", result)

    def test_extract_pf_search_context_missing_assignee(self) -> None:
        """Verifies graceful handling of unassigned tasks."""
        payload: dict[str, Any] = {"id": "5678", "title": "Unassigned Task"}

        result = _extract_pf_search_context(payload)
        self.assertEqual(result, "5678 | Unassigned Task")

    def test_extract_pf_search_context_empty_payload(self) -> None:
        """Verifies safe fallback when encountering completely empty payloads."""
        self.assertEqual(_extract_pf_search_context({}), "")

    async def test_audit_dashboard_search_vector_hit(self) -> None:
        """Verifies that queries successfully match against the search_vector column in the real DB."""
        # 1. Seed the isolated in-memory database
        async with self.test_session_maker() as session:
            log_target = SyncAuditLog(
                pf_task_id="100",
                jira_issue_key="HR-10",
                operation=SyncOperation.CREATE,
                details="{}",
                search_vector="1234 | Onboard new employee | ray@example.com",
            )
            log_noise = SyncAuditLog(
                pf_task_id="101",
                jira_issue_key="HR-11",
                operation=SyncOperation.UPDATE,
                details="{}",
                search_vector="5678 | Unrelated Task | someone_else@example.com",
            )
            session.add_all([log_target, log_noise])
            await session.commit()

        # 2. Setup mock request and params
        mock_request = MagicMock()
        mock_request.headers = {}
        params = MockAuditParams(page=1, query="ray@example.com")
        mock_user = {"email": "admin@example.com"}

        # 3. Intercept the template renderer to inspect the context safely
        with patch("src.app.admin.templates.TemplateResponse") as mock_template:
            async with self.test_session_maker() as session:
                await audit_dashboard(request=mock_request, params=params, session=session, user=mock_user)

            # 4. Validate robust database execution
            mock_template.assert_called_once()

            # Extract the context dictionary passed to Jinja2 (second positional argument)
            context = mock_template.call_args[0][1]
            logs = context["logs"]

            self.assertEqual(len(logs), 1)
            self.assertEqual(logs[0].jira_issue_key, "HR-10")
            self.assertEqual(logs[0].search_vector, "1234 | Onboard new employee | ray@example.com")


if __name__ == "__main__":
    unittest.main()
