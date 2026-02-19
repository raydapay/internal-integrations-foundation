from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from loguru import logger
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from src.core.database import get_session
from src.core.security import get_oauth
from src.domain.users.models import User

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _get_https_redirect_uri(request: Request, route_name: str) -> str:
    """Constructs a secure redirect URI, accounting for reverse proxies.

    Args:
        request: The incoming HTTP request.
        route_name: The name of the FastAPI route to resolve.

    Returns:
        str: The absolute URL with the correct scheme.
    """
    redirect_uri = str(request.url_for(route_name))
    if request.headers.get("x-forwarded-proto") == "https":
        redirect_uri = redirect_uri.replace("http://", "https://", 1)
    return redirect_uri


@router.get("/login")
async def login(request: Request) -> RedirectResponse:
    """Initiates the Google OAuth2 flow.

    Args:
        request: The incoming HTTP request.

    Returns:
        RedirectResponse: Redirection to the Google authorization endpoint.
    """
    oauth = get_oauth()
    redirect_uri = _get_https_redirect_uri(request, "auth_google")
    return await oauth.google.authorize_redirect(request, redirect_uri)


@router.get("/google", name="auth_google")
async def auth_google(
    request: Request, session: Annotated[AsyncSession, Depends(get_session)]
) -> RedirectResponse:
    """Callback for Google OAuth2. Handles JIT user provisioning.

    Args:
        request: The incoming HTTP request containing the authorization code.
        session: The injected asynchronous database session.

    Returns:
        RedirectResponse: Redirection to the application root upon success.

    Raises:
        HTTPException: If the token exchange fails or user info is missing.
    """
    oauth = get_oauth()
    try:
        token = await oauth.google.authorize_access_token(request)
    except Exception as e:
        logger.error(f"OAuth token exchange failed: {e}")
        raise HTTPException(status_code=400, detail="Authentication failed")  # noqa: B904

    user_info = token.get("userinfo")
    if not user_info:
        logger.error("No userinfo in token")
        raise HTTPException(status_code=400, detail="No user info received")

    email = user_info.get("email")

    statement = select(User).where(User.email == email)
    result = await session.exec(statement)
    user = result.first()

    if not user:
        logger.info(f"Provisioning new user: {email}")
        user = User(
            email=email,
            full_name=user_info.get("name", "Unknown"),
            avatar_url=user_info.get("picture"),
        )
        session.add(user)
    else:
        user.last_login = datetime.utcnow()
        user.avatar_url = user_info.get("picture")
        user.full_name = user_info.get("name", user.full_name)
        session.add(user)

    await session.commit()
    await session.refresh(user)

    request.session["user"] = {
        "id": user.id,
        "email": user.email,
        "name": user.full_name,
        "picture": user.avatar_url,
    }

    logger.info(f"User logged in: {email}")
    return RedirectResponse(url="/")


@router.get("/logout")
async def logout(request: Request) -> RedirectResponse:
    """Clears the session.

    Args:
        request: The incoming HTTP request.

    Returns:
        RedirectResponse: Redirection to the application root.
    """
    request.session.pop("user", None)
    return RedirectResponse(url="/")
