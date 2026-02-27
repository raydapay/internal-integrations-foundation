import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import httpx

from src.core.notifications import notify, send_slack, send_telegram


class TestNotifications(unittest.IsolatedAsyncioTestCase):
    """Test suite for the async notification dispatcher and fallback matrix."""

    @patch("src.core.notifications.settings")
    @patch("src.core.notifications.httpx.AsyncClient")
    async def test_send_slack_success(self, mock_client_class: MagicMock, mock_settings: MagicMock) -> None:
        """Verifies successful Slack delivery returns True."""
        mock_settings.SLACK_WEBHOOK_URL = "https://hooks.slack.com/fake"

        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_client.post.return_value = mock_response

        result = await send_slack("Test Alert")

        self.assertTrue(result)
        mock_client.post.assert_awaited_once()

    @patch("src.core.notifications.settings")
    @patch("src.core.notifications.httpx.AsyncClient")
    async def test_send_slack_failure(self, mock_client_class: MagicMock, mock_settings: MagicMock) -> None:
        """Verifies network timeouts or 4xx/5xx errors are caught and return False."""
        mock_settings.SLACK_WEBHOOK_URL = "https://hooks.slack.com/fake"

        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_client.post.side_effect = httpx.TimeoutException("Connection dropped")

        result = await send_slack("Test Alert")

        self.assertFalse(result)

    @patch("src.core.notifications.settings")
    async def test_send_slack_unconfigured(self, mock_settings: MagicMock) -> None:
        """Verifies execution short-circuits gracefully if the webhook URL is missing."""
        mock_settings.SLACK_WEBHOOK_URL = None
        result = await send_slack("Test Alert")
        self.assertFalse(result)

    @patch("src.core.notifications.settings")
    @patch("src.core.notifications.httpx.AsyncClient")
    async def test_send_telegram_success(self, mock_client_class: MagicMock, mock_settings: MagicMock) -> None:
        """Verifies successful Telegram delivery returns True."""
        mock_settings.TELEGRAM_BOT_TOKEN = "bot123"
        mock_settings.TELEGRAM_CHAT_ID = "chat123"

        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_client.post.return_value = mock_response

        result = await send_telegram("Test Alert")

        self.assertTrue(result)
        mock_client.post.assert_awaited_once()

    @patch("src.core.notifications.logger")
    @patch("src.core.notifications.send_telegram")
    @patch("src.core.notifications.send_slack")
    async def test_notify_primary_success(
        self, mock_send_slack: AsyncMock, mock_send_telegram: AsyncMock, mock_logger: MagicMock
    ) -> None:
        """Verifies the reserve channel is bypassed if the primary channel succeeds."""
        mock_send_slack.return_value = True

        await notify("Test message")

        mock_send_slack.assert_awaited_once()
        mock_send_telegram.assert_not_called()

    @patch("src.core.notifications.logger")
    @patch("src.core.notifications.send_telegram")
    @patch("src.core.notifications.send_slack")
    async def test_notify_fallback_triggered(
        self, mock_send_slack: AsyncMock, mock_send_telegram: AsyncMock, mock_logger: MagicMock
    ) -> None:
        """Verifies a failure in the primary channel triggers the reserve channel."""
        mock_send_slack.return_value = False
        mock_send_telegram.return_value = True

        await notify("Test message")

        mock_send_slack.assert_awaited_once()
        mock_send_telegram.assert_awaited_once()
        mock_logger.warning.assert_called_once()

    @patch("src.core.notifications.logger")
    @patch("src.core.notifications.send_telegram")
    @patch("src.core.notifications.send_slack")
    async def test_notify_catastrophic_failure(
        self, mock_send_slack: AsyncMock, mock_send_telegram: AsyncMock, mock_logger: MagicMock
    ) -> None:
        """Verifies complete observability blackout logs a critical error."""
        mock_send_slack.return_value = False
        mock_send_telegram.return_value = False

        await notify("Test message")

        mock_send_slack.assert_awaited_once()
        mock_send_telegram.assert_awaited_once()
        mock_logger.critical.assert_called_once()


if __name__ == "__main__":
    unittest.main()
