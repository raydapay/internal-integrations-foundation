import time
import uuid
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from loguru import logger
from sqlmodel import SQLModel
from starlette.middleware.sessions import SessionMiddleware

from src.config.settings import settings
from src.core.database import engine
from src.core.logger import configure_logging
from src.domain.users.router import router as auth_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manages the startup and shutdown lifecycle of the FastAPI application.

    Args:
        app: The FastAPI application instance.
    """
    configure_logging()

    # Initialize SQLite schema
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

    yield


# --- Application Setup ---
app = FastAPI(
    title=settings.APP_NAME,
    debug=settings.DEBUG,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url=None
)

# --- Middleware ---
# SessionMiddleware is required for Authlib to store the temporary state
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SECRET_KEY,
    max_age=3600 * 24 * 7,  # 7 days
    https_only=not settings.DEBUG  # Allow HTTP in dev, HTTPS in prod
)


@app.middleware("http")
async def request_id_middleware(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
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

            logger.info(
                f"Completed {response.status_code} in {process_time:.4f}s"
            )
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
            "request_id": request.headers.get("X-Request-ID", "unknown")
        }
    )


# --- Routing ---
app.include_router(auth_router)

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
    return {"status": "ok", "service": settings.APP_NAME}


# Temporary endpoint to verify auth works (until we have frontend)
@app.get("/")
async def home(request: Request) -> dict[str, str | dict]:
    """Root endpoint to verify authentication state.

    Args:
        request: The incoming HTTP request.

    Returns:
        dict: The current authentication status and user details if logged in.
    """
    user = request.session.get('user')
    if user:
        return {"status": "Authenticated", "user": user, "action": "Go to /auth/logout"}
    return {"status": "Anonymous", "action": "Go to /auth/login"}