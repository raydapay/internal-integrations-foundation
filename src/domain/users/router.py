from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from loguru import logger
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from src.config.settings import settings
from src.core.database import get_session
from src.core.security import get_oauth
from src.domain.users.models import User, UserRole

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
async def auth_google(request: Request, session: Annotated[AsyncSession, Depends(get_session)]) -> RedirectResponse:
    """Callback for Google OAuth2. Handles JIT user provisioning and identity sync.

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
        raise HTTPException(status_code=400, detail="Authentication failed") from e

    user_info = token.get("userinfo")
    if not user_info:
        logger.error("No userinfo in token")
        raise HTTPException(status_code=400, detail="No user info received")

    email = user_info.get("email")
    sso_name = user_info.get("name", "Unknown")
    sso_picture = user_info.get("picture")

    statement = select(User).where(User.email == email)
    result = await session.exec(statement)
    user = result.first()

    # Bootstrap the initial admin if configured in settings
    is_initial_admin = getattr(settings, "INITIAL_ADMIN_EMAIL", None) == email

    if not user:
        # 1. Standard JIT Provisioning for completely unknown users
        logger.info(f"Provisioning new JIT user: {email} (Active: {is_initial_admin})")
        user = User(
            email=email,
            full_name=sso_name,
            avatar_url=sso_picture,
            is_active=is_initial_admin,
            role=UserRole.SYSTEM_ADMIN if is_initial_admin else UserRole.VIEWER,
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
    else:
        # 2. Identity Synchronization for pre-provisioned or returning users
        db_mutated = False

        # Overwrite the placeholder if the user was pre-provisioned by an admin
        if user.full_name in ["Pending SSO Login", "Unknown"] or not user.full_name:
            user.full_name = sso_name
            db_mutated = True

        # Keep the avatar fresh if they changed it on their Google account
        if user.avatar_url != sso_picture:
            user.avatar_url = sso_picture
            db_mutated = True

        if db_mutated:
            logger.info(f"Synchronizing SSO identity payload for existing user: {email}")
            session.add(user)
            await session.commit()
            await session.refresh(user)

    if not user.is_active:
        logger.warning(f"Blocked login for inactive user: {email}")
        raise HTTPException(status_code=403, detail="Account created but pending administrator approval.")

    # Proceed with setting session
    request.session["user"] = {
        "id": user.id,
        "email": user.email,
        "name": user.full_name,
        "picture": user.avatar_url,
        "role": user.role.value,  # Inject role into session for UI routing
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
