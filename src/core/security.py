import hashlib
import hmac

from authlib.integrations.starlette_client import OAuth
from fastapi import HTTPException, Request, Security
from fastapi.security import APIKeyHeader
from loguru import logger
from starlette.config import Config

from src.config.settings import settings

# Jira sends the HMAC signature in this header
jira_signature_header = APIKeyHeader(name="X-Hub-Signature", auto_error=False)

# We bridge Pydantic settings to Starlette's Config interface expected by Authlib
config_data = {
    "GOOGLE_CLIENT_ID": settings.GOOGLE_CLIENT_ID,
    "GOOGLE_CLIENT_SECRET": settings.GOOGLE_CLIENT_SECRET,
}
starlette_config = Config(environ=config_data)

oauth = OAuth(starlette_config)

oauth.register(
    name="google",
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)


def get_oauth() -> OAuth:
    """Retrieves the configured Authlib OAuth instance.

    Returns:
        OAuth: The registered OAuth client for Google SSO.
    """
    return oauth


async def verify_jira_webhook_signature(
    request: Request, signature_header: str | None = Security(jira_signature_header)
) -> bytes:
    """Validates signature and yields the raw body to prevent ASGI stream deadlocks."""
    if not settings.JIRA_WEBHOOK_SECRET:
        logger.error("JIRA_WEBHOOK_SECRET is null. Failing closed.")
        raise HTTPException(status_code=500, detail="Configuration missing.")

    if not signature_header:
        logger.warning("Rejected Webhook: Missing X-Hub-Signature header.")
        raise HTTPException(status_code=401, detail="Missing signature.")

    # Await the stream exactly once
    raw_body = await request.body()

    try:
        provided_hash = signature_header.split("=")[1]
    except IndexError as e:
        logger.warning(f"Rejected Webhook: Malformed signature header -> {signature_header}")
        raise HTTPException(status_code=400, detail="Malformed signature.") from e

    secret_bytes = settings.JIRA_WEBHOOK_SECRET.encode("utf-8")
    calculated_mac = hmac.new(secret_bytes, msg=raw_body, digestmod=hashlib.sha256)
    calculated_hash = calculated_mac.hexdigest()

    if not hmac.compare_digest(provided_hash, calculated_hash):
        logger.warning(f"Signature mismatch. Expected: {calculated_hash}, Got: {provided_hash}")
        raise HTTPException(status_code=403, detail="Signature mismatch.")

    logger.debug(f"Jira Webhook cryptographic signature validated ({len(raw_body)} bytes).")
    return raw_body
