import httpx
from loguru import logger

from src.config.settings import settings


async def send_slack(message: str) -> bool:
    """Dispatches alert to Slack via webhook asynchronously."""
    if not settings.SLACK_WEBHOOK_URL:
        return False

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                settings.SLACK_WEBHOOK_URL, json={"text": f"🚨 *PF-Jira Gateway Alert* 🚨\n\n{message}"}
            )
            resp.raise_for_status()
        return True
    except Exception as e:
        logger.error(f"Slack notification failed: {e}")
        return False


async def send_telegram(message: str) -> bool:
    """Dispatches alert to Telegram asynchronously."""
    if not settings.TELEGRAM_BOT_TOKEN or not settings.TELEGRAM_CHAT_ID:
        return False

    url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/sendMessage"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                url,
                json={
                    "chat_id": settings.TELEGRAM_CHAT_ID,
                    "text": f"🚨 *PF-Jira Gateway Alert* 🚨\n\n{message}",
                    "parse_mode": "Markdown",
                },
            )
            resp.raise_for_status()
        return True
    except Exception as e:
        logger.error(f"Telegram notification failed: {e}")
        return False


async def notify(message: str) -> None:
    """
    Unified asynchronous notification dispatcher.
    Attempts primary channel (Slack), falls back to reserve (Telegram).
    """
    slack_delivered = await send_slack(message)

    if not slack_delivered:
        logger.warning("Primary notification (Slack) skipped or failed. Engaging reserve (Telegram).")
        telegram_delivered = await send_telegram(message)

        if not telegram_delivered:
            logger.critical(f"All notification channels failed. Undelivered alert: {message}")
