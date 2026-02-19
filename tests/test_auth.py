import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi.responses import RedirectResponse
from fastapi.testclient import TestClient

from src.app.main import app


class TestAuthEndpoints(unittest.IsolatedAsyncioTestCase):
    """Test suite for authentication routing and OAuth redirects."""

    def setUp(self) -> None:
        """Initializes the synchronous test client for route testing."""
        self.client = TestClient(app)

    @patch("src.domain.users.router.get_oauth")
    def test_login_redirects_to_google_with_https(self, mock_get_oauth: MagicMock) -> None:
        """Validates that the login endpoint respects the X-Forwarded-Proto header.

        Args:
            mock_get_oauth: Mocked Authlib OAuth instance.
        """
        mock_oauth_instance = MagicMock()
        mock_get_oauth.return_value = mock_oauth_instance

        # AsyncMock ensures the await expression in the router evaluates correctly
        mock_oauth_instance.google.authorize_redirect = AsyncMock(
            return_value=RedirectResponse(url="https://accounts.google.com/o/oauth2/v2/auth")
        )

        # Simulate incoming request from Cloudflare edge
        headers = {"X-Forwarded-Proto": "https", "Host": "pf-jira-sync.todaserv.com"}

        # Disable redirect following to capture the immediate response from the router
        response = self.client.get("/auth/login", headers=headers, follow_redirects=False)

        # Verify Authlib was called
        mock_oauth_instance.google.authorize_redirect.assert_called_once()

        # Extract the redirect_uri passed to Authlib
        args, kwargs = mock_oauth_instance.google.authorize_redirect.call_args
        redirect_uri = kwargs.get("redirect_uri") if "redirect_uri" in kwargs else args[1]

        self.assertEqual(response.status_code, 307)
        self.assertTrue(redirect_uri.startswith("https://"), "Redirect URI did not force HTTPS.")


if __name__ == "__main__":
    unittest.main()
