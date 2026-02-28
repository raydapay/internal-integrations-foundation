import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
from starlette.datastructures import URL

# Adjust the import path depending on where you placed the function
from src.core.security import check_google_sso_config


class TestSSOHealthCheck(unittest.IsolatedAsyncioTestCase):
    """Test suite for the proactive Google SSO configuration dry-run."""

    def setUp(self) -> None:
        """Initializes the mock HTTP request to accurately reflect reverse proxy headers."""
        self.mock_request = MagicMock()
        self.mock_request.url_for.return_value = URL("http://gateway.local/auth/google")
        self.mock_request.headers = {"x-forwarded-proto": "https"}

    @patch("src.core.security.settings")
    async def test_missing_client_id(self, mock_settings: MagicMock) -> None:
        """Verifies the check gracefully short-circuits if the environment is unconfigured."""
        mock_settings.GOOGLE_CLIENT_ID = None

        is_valid, detail = await check_google_sso_config(self.mock_request)

        self.assertFalse(is_valid)
        self.assertIn("Missing GOOGLE_CLIENT_ID", detail)

    @patch("src.core.security.settings")
    @patch("src.core.security.httpx.AsyncClient")
    async def test_valid_configuration(self, mock_client_class: MagicMock, mock_settings: MagicMock) -> None:
        """Verifies a 200 OK from the Authorization Endpoint indicates a healthy configuration."""
        mock_settings.GOOGLE_CLIENT_ID = "valid-client-id"

        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_client.get.return_value = mock_response

        is_valid, detail = await check_google_sso_config(self.mock_request)

        self.assertTrue(is_valid)
        self.assertEqual(detail, "Configured & URI Whitelisted")

        # Verify it enforces https upgrade
        _, kwargs = mock_client.get.call_args
        self.assertEqual(kwargs["params"]["redirect_uri"], "https://gateway.local/auth/google")
        self.assertFalse(kwargs["follow_redirects"])

    @patch("src.core.security.settings")
    @patch("src.core.security.httpx.AsyncClient")
    async def test_uri_mismatch_detection(self, mock_client_class: MagicMock, mock_settings: MagicMock) -> None:
        """Verifies parsing of the specific redirect_uri_mismatch error from Google's HTML."""
        mock_settings.GOOGLE_CLIENT_ID = "valid-client-id"

        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.text = "<html>Error: redirect_uri_mismatch Details...</html>"
        mock_client.get.return_value = mock_response

        is_valid, detail = await check_google_sso_config(self.mock_request)

        self.assertFalse(is_valid)
        self.assertIn("URI Mismatch", detail)

    @patch("src.core.security.settings")
    @patch("src.core.security.httpx.AsyncClient")
    async def test_invalid_client_detection(self, mock_client_class: MagicMock, mock_settings: MagicMock) -> None:
        """Verifies parsing of the invalid_client error (e.g., project deleted)."""
        mock_settings.GOOGLE_CLIENT_ID = "deleted-client-id"

        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.text = "<html>Error: invalid_client Details...</html>"
        mock_client.get.return_value = mock_response

        is_valid, detail = await check_google_sso_config(self.mock_request)

        self.assertFalse(is_valid)
        self.assertIn("Invalid Client ID", detail)

    @patch("src.core.security.settings")
    @patch("src.core.security.httpx.AsyncClient")
    async def test_network_timeout(self, mock_client_class: MagicMock, mock_settings: MagicMock) -> None:
        """Verifies standard network exceptions are caught and reported cleanly."""
        mock_settings.GOOGLE_CLIENT_ID = "valid-client-id"

        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_client.get.side_effect = httpx.ConnectTimeout("Google is down")

        is_valid, detail = await check_google_sso_config(self.mock_request)

        self.assertFalse(is_valid)
        self.assertIn("Network timeout", detail)
        self.assertIn("ConnectTimeout", detail)


if __name__ == "__main__":
    unittest.main()
