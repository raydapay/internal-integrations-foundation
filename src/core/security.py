import hashlib
import hmac

import httpx
from authlib.integrations.starlette_client import OAuth
from fastapi import HTTPException, Request, Security, status
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
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Configuration missing.")

    if not signature_header:
        logger.warning("Rejected Webhook: Missing X-Hub-Signature header.")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing signature.")

    # Await the stream exactly once
    raw_body = await request.body()

    try:
        provided_hash = signature_header.split("=")[1]
    except IndexError as e:
        logger.warning(f"Rejected Webhook: Malformed signature header -> {signature_header}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Malformed signature.") from e

    secret_bytes = settings.JIRA_WEBHOOK_SECRET.encode("utf-8")
    calculated_mac = hmac.new(secret_bytes, msg=raw_body, digestmod=hashlib.sha256)
    calculated_hash = calculated_mac.hexdigest()

    if not hmac.compare_digest(provided_hash, calculated_hash):
        logger.warning(f"Signature mismatch. Expected: {calculated_hash}, Got: {provided_hash}")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Signature mismatch.")

    logger.debug(f"Jira Webhook cryptographic signature validated ({len(raw_body)} bytes).")
    return raw_body


async def check_google_sso_config(request: Request) -> tuple[bool, str]:
    """
    Performs a dry-run against Google's Authorization endpoint to detect config drift.

    Args:
        request: The incoming FastAPI request used to resolve the host URI.

    Returns:
        tuple[bool, str]: A boolean indicating validity, and a descriptive status message.
    """
    if not settings.GOOGLE_CLIENT_ID:
        return False, "Missing GOOGLE_CLIENT_ID in environment."

    # Dynamically resolve the expected URI based on the current Host header
    redirect_uri = str(request.url_for("auth_google"))
    if request.headers.get("x-forwarded-proto") == "https":
        redirect_uri = redirect_uri.replace("http://", "https://", 1)

    auth_url = "https://accounts.google.com/o/oauth2/v2/auth"
    params = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "email profile",
    }

    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            response = await client.get(auth_url, params=params, follow_redirects=False)

            if response.status_code == status.HTTP_400_BAD_REQUEST:
                # Consolidate the 400 error returns to satisfy Ruff PLR0911
                if "redirect_uri_mismatch" in response.text:
                    err_detail = f"URI Mismatch: {redirect_uri} is not whitelisted in GCP Console."
                elif "invalid_client" in response.text:
                    err_detail = "Invalid Client ID: Project deleted or ID revoked."
                else:
                    err_detail = "Configuration error (HTTP 400)."
                return False, err_detail

            if response.status_code in (status.HTTP_200_OK, status.HTTP_302_FOUND):
                return True, "Configured & URI Whitelisted"

            return False, f"Unexpected upstream response: {response.status_code}"

    except httpx.RequestError as e:
        return False, f"Network timeout reaching Google: {type(e).__name__}"
