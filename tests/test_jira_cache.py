import unittest
from unittest.mock import AsyncMock, MagicMock

import httpx

from src.core.clients import JiraClient


class TestJiraClient(unittest.IsolatedAsyncioTestCase):
    """Verifies Jira API client behaviors, including caching and permissions."""

    async def asyncSetUp(self) -> None:
        self.client = JiraClient()
        self.client.client = MagicMock()
        self.client.transition_issue = AsyncMock()

    async def test_transition_cache_hit(self) -> None:
        """Verifies that subsequent calls use the cached transition ID without network I/O."""
        self.client._transition_cache = {"HR": "41"}

        await self.client.transition_issue_to_done("HR-123")

        # Ensure the GET transitions endpoint was completely bypassed
        self.client.client.get.assert_not_called()
        self.client.transition_issue.assert_awaited_once_with("HR-123", "41")

    async def test_transition_cache_invalidation_on_400(self) -> None:
        """Verifies that a 400 Bad Request evicts the stale cache and successfully retries."""
        self.client._transition_cache = {"IT": "99"}

        # First call fails (stale cache), Second call succeeds (recovered)
        mock_post_response = httpx.Response(status_code=400, request=httpx.Request("POST", ""))
        self.client.transition_issue.side_effect = [
            httpx.HTTPStatusError(
                "Invalid transition", request=mock_post_response.request, response=mock_post_response
            ),
            None,
        ]

        # Correctly mock the fallback GET request that fetches the fresh transitions
        mock_get_resp = MagicMock()
        mock_get_resp.json.return_value = {"transitions": [{"id": "100", "to": {"statusCategory": {"key": "done"}}}]}
        self.client.client.get = AsyncMock(return_value=mock_get_resp)

        # Execute the function (it should NOT raise an exception because it self-heals)
        await self.client.transition_issue_to_done("IT-404")

        # Verify the cache was updated to the newly discovered transition ID
        self.assertEqual(self.client._transition_cache["IT"], "100")

        # Verify transition_issue was called twice (once with bad cache, once with fresh data)
        self.assertEqual(self.client.transition_issue.call_count, 2)

    async def test_validate_project_permissions_success(self) -> None:
        """Verifies true matrix evaluation when a token possesses all required rights."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "permissions": {
                "CREATE_ISSUES": {"havePermission": True},
                "EDIT_ISSUES": {"havePermission": True},
                "ASSIGN_ISSUES": {"havePermission": True},
                "MODIFY_REPORTER": {"havePermission": True},
                "TRANSITION_ISSUES": {"havePermission": True},
                "ADD_COMMENTS": {"havePermission": True},
            }
        }
        self.client.client.get = AsyncMock(return_value=mock_response)

        is_valid, missing = await self.client.validate_project_permissions("HR")

        self.assertTrue(is_valid)
        self.assertEqual(len(missing), 0)

    async def test_validate_project_permissions_missing(self) -> None:
        """Verifies the API correctly identifies and reports specific missing rights."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "permissions": {
                "CREATE_ISSUES": {"havePermission": True},
                "EDIT_ISSUES": {"havePermission": False},  # Missing
                "ASSIGN_ISSUES": {"havePermission": True},
                "MODIFY_REPORTER": {"havePermission": False},  # Missing
                "TRANSITION_ISSUES": {"havePermission": True},
                "ADD_COMMENTS": {"havePermission": True},
            }
        }
        self.client.client.get = AsyncMock(return_value=mock_response)

        is_valid, missing = await self.client.validate_project_permissions("IT")

        self.assertFalse(is_valid)
        self.assertEqual(len(missing), 2)
        self.assertIn("EDIT_ISSUES", missing)
        self.assertIn("MODIFY_REPORTER", missing)


if __name__ == "__main__":
    unittest.main()
