import asyncio
import time
import uuid
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Any

import arq
from arq.connections import RedisSettings
from fastapi import FastAPI, Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from loguru import logger
from sqlmodel import SQLModel
from starlette.middleware.sessions import SessionMiddleware

from src import version
from src.app.admin import router as admin_router
from src.app.webhooks import router as webhook_router
from src.config.settings import settings
from src.core.broadcaster import configure_sse_logger
from src.core.clients import HTTPClientManager, NotificationClient
from src.core.database import engine
from src.core.logger import configure_logging
from src.domain.pf_jira.router import router as pf_jira_router
from src.domain.users.router import router as auth_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manages the startup and shutdown lifecycle of the FastAPI application."""
    configure_logging()
    configure_sse_logger()

    # Initialize SQLite schema
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

    # Initialize ARQ Redis Pool
    redis_settings = RedisSettings.from_dsn(settings.REDIS_URL)
    app.state.arq_pool = await arq.create_pool(redis_settings)

    yield

    # Teardown
    await app.state.arq_pool.close()
    await HTTPClientManager.teardown()


# --- Application Setup ---
app = FastAPI(
    title=settings.APP_NAME,
    debug=settings.DEBUG,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url=None,
)

# --- Middleware ---
# SessionMiddleware is required for Authlib to store the temporary state
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SECRET_KEY,
    max_age=3600 * 24 * 7,  # 7 days
    https_only=not settings.DEBUG,  # Allow HTTP in dev, HTTPS in prod
)


@app.middleware("http")
async def request_id_middleware(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    """Injects a unique Request-ID into the logging context and response headers.

    Args:
        request: The incoming HTTP request.
        call_next: The next middleware or route handler in the pipeline.

    Returns:
        Response: The HTTP response with injected tracking headers.
    """
    request_id = str(uuid.uuid4())

    with logger.contextualize(request_id=request_id):
        logger.info(f"Started {request.method} {request.url.path}")
        start_time = time.perf_counter()

        try:
            response = await call_next(request)
            process_time = time.perf_counter() - start_time

            response.headers["X-Request-ID"] = request_id
            response.headers["X-Process-Time"] = str(process_time)

            logger.info(f"Completed {response.status_code} in {process_time:.4f}s")
            return response
        except Exception as e:
            process_time = time.perf_counter() - start_time
            logger.error(f"Request failed after {process_time:.4f}s: {e}")
            raise


# --- Exception Handlers ---
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catches unhandled exceptions and returns a standardized JSON response.

    Args:
        request: The incoming HTTP request.
        exc: The raised exception.

    Returns:
        JSONResponse: A 500 Internal Server Error payload.
    """
    logger.exception("Unhandled server exception")
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "message": "An unexpected error occurred.",
            "request_id": request.headers.get("X-Request-ID", "unknown"),
        },
    )


# --- Routing ---
app.include_router(auth_router)
app.include_router(pf_jira_router)
app.include_router(admin_router)
app.include_router(webhook_router)

# Mount static files and templates only if the directories exist
try:
    app.mount("/static", StaticFiles(directory="src/static"), name="static")
    templates = Jinja2Templates(directory="src/templates")
except RuntimeError as e:
    logger.warning(f"Static or template directory missing, skipping mount: {e}")


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Provides a basic health check for the application.

    Returns:
        dict: The application status and name.
    """
    return {
        "status": "ok",
        "service": settings.APP_NAME,
        "version": version.VERSION,
        "build_time": version.BUILD_TIMESTAMP,
    }


@app.get("/")
async def home(request: Request) -> Response:
    """Root endpoint that routes users based on authentication state."""
    user = request.session.get("user")
    if user:
        # Redirect authenticated users straight to the health dashboard
        return RedirectResponse(url="/admin/health", status_code=status.HTTP_303_SEE_OTHER)

    # Redirect anonymous users to the SSO flow
    return RedirectResponse(url="/auth/login", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/api/v1/health", tags=["System"])
async def api_health_check(request: Request) -> dict[str, Any]:
    """Provides a strict JSON health payload for external monitors (e.g., Zabbix).

    Returns:
        dict[str, Any]: System versioning and infrastructure heartbeat metrics.
    """
    arq_pool = getattr(request.app.state, "arq_pool", None)
    workers_alive = 0

    if arq_pool:
        try:
            # Query Redis for ARQ's ephemeral worker heartbeat keys
            worker_keys = await arq_pool.keys("arq:worker:*")
            workers_alive = len(worker_keys)
        except Exception as e:
            logger.error(f"Failed to ping Redis for worker heartbeat: {e}")

    # Flag degraded if no workers are alive to process the queues
    status_flag = "ok" if workers_alive > 0 else "degraded"

    notify_client = NotificationClient()
    try:
        slack_res, tg_res = await asyncio.gather(notify_client.ping_slack(), notify_client.ping_telegram())
    except Exception as e:
        logger.error(f"Health check external ping failed catastrophically: {e}")
        slack_res = ("danger", "Ping execution failed")
        tg_res = ("danger", "Ping execution failed")
    finally:
        await notify_client.close()

    # Optional: If both notification channels are dead, the system cannot alert humans.
    if slack_res[0] == "danger" and tg_res[0] == "danger":
        status_flag = "degraded"

    return {
        "status": status_flag,
        "service": settings.APP_NAME,
        "version": getattr(version, "VERSION", "unknown"),
        "workers_active": workers_alive,
        "integrations": {
            "slack": {"status": "ok" if slack_res[0] == "success" else slack_res[0], "detail": slack_res[1]},
            "telegram": {"status": "ok" if tg_res[0] == "success" else tg_res[0], "detail": tg_res[1]},
        },
    }
