import unittest
from unittest.mock import AsyncMock, patch

from fastapi import Request
from fastapi.templating import Jinja2Templates

from src.app.admin import audit_dashboard
from src.domain.pf_jira.models import SyncAuditLog, SyncOperation
from tests.base import BaseTest


class TestAuditAPI(BaseTest):
    """Test suite for the Sync Audit Log dashboard endpoints."""

    def setUp(self) -> None:
        """Sets up standard mock request dependencies."""
        self.mock_request = AsyncMock(spec=Request)
        self.mock_request.headers = {}
        self.mock_user = {"id": 1, "email": "admin@todapay.com", "role": "system_admin"}

    async def _seed_audit_logs(self, count: int, search_term: str = "HR-10") -> None:
        """Helper to seed the in-memory database with test audit logs."""
        async with self.test_session_maker() as session:
            logs = []
            for i in range(count):
                logs.append(
                    SyncAuditLog(
                        jira_issue_key=f"{search_term}-{i}",
                        pf_task_id=f"100{i}",
                        operation=SyncOperation.CREATE,
                        details="Test details",
                    )
                )
            session.add_all(logs)
            await session.commit()

    @patch("src.app.admin.templates", spec=Jinja2Templates)
    async def test_audit_dashboard_standard_request(self, mock_templates: AsyncMock) -> None:
        """Verifies standard browser requests return the full HTML layout."""
        # Seed 2 items (less than page_size of 50, so has_next = False)
        await self._seed_audit_logs(count=2)

        async with self.test_session_maker() as session:
            await audit_dashboard(request=self.mock_request, query=None, page=1, session=session, user=self.mock_user)

        mock_templates.TemplateResponse.assert_called_once()
        args, _ = mock_templates.TemplateResponse.call_args

        self.assertEqual(args[0], "audit.html")
        self.assertFalse(args[1]["has_next"])
        self.assertEqual(len(args[1]["logs"]), 2)

    @patch("src.app.admin.templates", spec=Jinja2Templates)
    async def test_audit_dashboard_htmx_search(self, mock_templates: AsyncMock) -> None:
        """Verifies HTMX requests return only the partial tbody HTML."""
        self.mock_request.headers = {"HX-Request": "true"}

        # Seed 51 items to trigger pagination logic (has_next = True)
        await self._seed_audit_logs(count=51, search_term="HR-10")

        async with self.test_session_maker() as session:
            await audit_dashboard(
                request=self.mock_request, query="HR-10", page=1, session=session, user=self.mock_user
            )

        mock_templates.TemplateResponse.assert_called_once()
        args, _ = mock_templates.TemplateResponse.call_args

        self.assertEqual(args[0], "partials/_audit_tbody.html")
        self.assertTrue(args[1]["has_next"])
        self.assertEqual(len(args[1]["logs"]), 50)  # Truncated to page size
        self.assertEqual(args[1]["query"], "HR-10")


if __name__ == "__main__":
    unittest.main()
