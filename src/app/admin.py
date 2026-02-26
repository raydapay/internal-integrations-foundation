import asyncio
import json
import time
from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from typing import Any

import httpx
import psutil
import redis.asyncio as redis
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from loguru import logger
from sqlalchemy.orm import selectinload
from sqlmodel import desc, or_, select
from sqlmodel.ext.asyncio.session import AsyncSession

from src.app.schemas import AuditQueryParams, UserAccessForm, UserProvisionForm
from src.config.settings import settings
from src.core.broadcaster import log_broadcaster
from src.core.clients import JiraClient, NotificationClient, PeopleForceClient
from src.core.database import get_session
from src.domain.pf_jira.models import (
    DomainConfig,
    MappingSourceType,
    RoutingAction,
    RoutingRule,
    RuleFieldMapping,
    SyncAuditLog,
)
from src.domain.pf_jira.resolver import FieldDataResolver
from src.domain.users.models import User, UserRole

router = APIRouter(prefix="/admin", tags=["Admin Dashboard"])
templates = Jinja2Templates(directory="src/templates")


def get_current_admin_user(request: Request) -> dict[str, Any]:
    """Dependency to secure the dashboard behind Google SSO."""
    user = request.session.get("user")
    if not user:
        if request.headers.get("HX-Request"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session expired. Please reload the page.",
            )
        # Redirect standard browser requests to the login flow
        raise HTTPException(status_code=status.HTTP_307_TEMPORARY_REDIRECT, headers={"Location": "/auth/login"})
    return user


def get_current_user(request: Request) -> dict[str, Any]:
    """Dependency to secure the dashboard behind Google SSO for all roles."""
    user = request.session.get("user")
    if not user:
        if request.headers.get("HX-Request"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session expired. Please reload the page.",
            )
        raise HTTPException(status_code=status.HTTP_307_TEMPORARY_REDIRECT, headers={"Location": "/auth/login"})
    return user


def require_system_admin(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    """Dependency to enforce absolute system administration privileges."""
    # Failsafe: Hard override for the initial bootstrap administrator
    if getattr(settings, "INITIAL_ADMIN_EMAIL", None) == user.get("email"):
        return user

    if user.get("role") != UserRole.SYSTEM_ADMIN.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="System Administrator privileges required.",
        )
    return user


def require_pf_jira_admin(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    """Dependency to enforce mutation privileges for PF-Jira tasks and rules."""
    # Failsafe: Hard override for the initial bootstrap administrator
    if getattr(settings, "INITIAL_ADMIN_EMAIL", None) == user.get("email"):
        return user

    role = user.get("role")

    if role not in [UserRole.SYSTEM_ADMIN.value, UserRole.PF_JIRA_ADMIN.value]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to modify the integration state.",
        )
    return user


@router.get("", include_in_schema=False)
@router.get("/", include_in_schema=False)
async def admin_root() -> Response:
    """Redirects the base /admin path to the default health dashboard."""
    return RedirectResponse(url="/admin/health", status_code=status.HTTP_303_SEE_OTHER)


# --- Split Dashboard Routes ---
# @router.get("/pf-jira/sync", response_class=HTMLResponse)
# async def sync_dashboard(
#     request: Request, user: dict[str, Any] = Depends(get_current_user)
# ) -> HTMLResponse:
#     """Renders the manual synchronization interface."""
#     return templates.TemplateResponse("sync.html", {"request": request, "user": user})


@router.get("/telemetry", response_class=HTMLResponse)
async def telemetry_dashboard(request: Request, user: dict[str, Any] = Depends(get_current_user)) -> HTMLResponse:
    """Renders the live SSE log streaming console."""
    return templates.TemplateResponse("telemetry.html", {"request": request, "user": user})


# --- Health Endpoint ---


@router.get("/health", response_class=HTMLResponse)
async def system_health(request: Request, user: dict[str, Any] = Depends(get_current_user)) -> HTMLResponse:
    """Aggregates hardware, infrastructure, and integration metrics."""

    # 1. Hardware Metrics
    mem = psutil.virtual_memory()
    uptime_seconds = time.time() - psutil.boot_time()
    uptime_str = f"{int(uptime_seconds // 3600)}h {int((uptime_seconds % 3600) // 60)}m"
    disk = psutil.disk_usage("/")

    # Handle OS-specific temperature limitations gracefully
    temps = "N/A (Windows/Unsupported)"
    if hasattr(psutil, "sensors_temperatures"):
        try:
            sensors = psutil.sensors_temperatures()
            if sensors and "coretemp" in sensors:
                temps = f"{sensors['coretemp'][0].current}°C"
        except Exception:
            pass

    hardware = {
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "mem_percent": mem.percent,
        "mem_used_gb": round(mem.used / (1024**3), 2),
        "mem_total_gb": round(mem.total / (1024**3), 2),
        "uptime": uptime_str,
        "temps": temps,
        "disk_free_gb": round(disk.free / (1024**3), 2),
        "disk_total_gb": round(disk.total / (1024**3), 2),
    }

    # 2. Infrastructure (ARQ Queue & Workers)
    arq_pool = getattr(request.app.state, "arq_pool", None)
    queue_depth = "Offline"
    workers_active = 0

    if arq_pool:
        try:
            # ARQ 0.25+ exposes queued_jobs
            queued = await arq_pool.queued_jobs(queue_name="pf_jira_queue")
            queue_depth = f"{len(queued)} jobs"

            # Fetch active worker heartbeats
            worker_keys = await arq_pool.keys("arq:worker:*")
            workers_active = len(worker_keys)
        except Exception:
            queue_depth = "Error reading queue"

    # 3. Integration Pings (Concurrent execution)
    pf_client = PeopleForceClient()
    jira_client = JiraClient()
    notify_client = NotificationClient()

    try:
        pf_res, jira_res, slack_res, tg_res = await asyncio.gather(
            pf_client.ping(), jira_client.ping(), notify_client.ping_slack(), notify_client.ping_telegram()
        )
    finally:
        await asyncio.gather(pf_client.close(), jira_client.close(), notify_client.close())

    integrations = {
        "peopleforce": {"status": "OK" if pf_res[0] else "ERROR", "detail": pf_res[1]},
        "jira": {"status": "OK" if jira_res[0] else "ERROR", "detail": jira_res[1]},
        "slack": {"status_tag": slack_res[0], "detail": slack_res[1]},
        "telegram": {"status_tag": tg_res[0], "detail": tg_res[1]},
    }

    return templates.TemplateResponse(
        "health.html",
        {
            "request": request,
            "user": user,
            "hardware": hardware,
            "queue_depth": queue_depth,
            "workers_active": workers_active,  # Inject the new variable here
            "integrations": integrations,
        },
    )


@router.get("/settings", response_class=HTMLResponse)
async def settings_dashboard(
    request: Request, user: dict[str, Any] = Depends(require_system_admin), session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    """Renders the global integration settings dashboard."""
    config = (await session.exec(select(DomainConfig).where(DomainConfig.domain_name == "pf_jira"))).first()

    jira_client = JiraClient()
    try:
        jira_projects = await jira_client.get_all_projects()
    finally:
        await jira_client.close()

    return templates.TemplateResponse(
        "settings.html", {"request": request, "user": user, "config": config, "jira_projects": jira_projects}
    )


@router.post("/settings", response_class=HTMLResponse)
async def update_settings(
    request: Request, session: AsyncSession = Depends(get_session), user: dict[str, Any] = Depends(require_system_admin)
) -> HTMLResponse:
    """HTMX endpoint to update global settings in real-time."""
    form_data = await request.form()

    is_active = form_data.get("is_active") is not None
    # Safe casting: String -> Float -> Int
    polling_interval_seconds = int(float(form_data.get("polling_interval_seconds", 300)))
    proj_raw = form_data.get("default_jira_project")
    default_jira_project = proj_raw.strip() if proj_raw else None

    # Parse health and alert configurations
    health_check_interval_seconds = int(float(form_data.get("health_check_interval_seconds", 900)))
    alert_mem_threshold_pct = float(form_data.get("alert_mem_threshold_pct", 90.0))
    alert_disk_threshold_pct = float(form_data.get("alert_disk_threshold_pct", 90.0))
    alert_queue_depth_threshold = int(float(form_data.get("alert_queue_depth_threshold", 500)))

    config = (await session.exec(select(DomainConfig).where(DomainConfig.domain_name == "pf_jira"))).first()
    if not config:
        return templates.TemplateResponse(
            "partials/_toast.html",
            {"request": request, "level": "danger", "message": "System error: DomainConfig not found."},
        )
    # Extract Jira configuration constants
    config.jira_pf_task_id_custom_field = form_data.get("jira_pf_task_id_custom_field", "customfield_10048").strip()

    fallback_acc = form_data.get("jira_fallback_account_id")
    config.jira_fallback_account_id = fallback_acc.strip() if fallback_acc else None

    config.is_active = is_active
    config.polling_interval_seconds = polling_interval_seconds
    config.default_jira_project = default_jira_project

    config.health_check_interval_seconds = health_check_interval_seconds
    config.alert_mem_threshold_pct = alert_mem_threshold_pct
    config.alert_disk_threshold_pct = alert_disk_threshold_pct
    config.alert_queue_depth_threshold = alert_queue_depth_threshold

    config.updated_at = datetime.now(UTC)

    session.add(config)
    await session.commit()

    return templates.TemplateResponse(
        "partials/_toast.html",
        {"request": request, "level": "success", "message": "Global settings updated successfully."},
    )


@router.post("/sync/pf-jira", response_class=HTMLResponse)
async def trigger_pf_jira_sync(request: Request, user: dict[str, Any] = Depends(require_pf_jira_admin)) -> HTMLResponse:
    """HTMX endpoint to manually trigger the ARQ worker."""
    arq_pool = getattr(request.app.state, "arq_pool", None)
    if not arq_pool:
        return templates.TemplateResponse(
            "partials/_toast.html",
            {"request": request, "level": "danger", "message": "ARQ Pool offline."},
        )

    await arq_pool.enqueue_job(
        "sync_pf_to_jira_task",
        {"email": user.get("email"), "manual_trigger": True},
        _queue_name="pf_jira_queue",
    )

    return templates.TemplateResponse(
        "partials/_toast.html",
        {"request": request, "level": "success", "message": "Sync job enqueued successfully."},
    )


@router.get("/stream/logs")
async def stream_logs(request: Request, user: dict[str, Any] = Depends(get_current_user)) -> StreamingResponse:
    """SSE endpoint streaming live Loguru JSON output to the browser."""

    async def event_generator() -> AsyncGenerator[str, None]:
        queue = log_broadcaster.subscribe()
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    # Cloudflare 100-Second Defeat Mechanism
                    # Yields a heartbeat ping every 15 seconds of inactivity
                    log_json = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield f"data: {log_json}\n\n"
                except TimeoutError:
                    yield ": ping\n\n"
        finally:
            log_broadcaster.unsubscribe(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # Defeats local Nginx buffering if used
        },
    )


@router.get("/rules", response_class=HTMLResponse)
async def rules_dashboard(
    request: Request,
    user: dict[str, Any] = Depends(get_current_admin_user),
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    """Renders the dynamic mapping rules management interface.

    Args:
        request: The incoming HTTP request.
        user: The authenticated user context.
        session: The asynchronous database session.

    Returns:
        HTMLResponse: The complete rendered dashboard.
    """
    # CRITICAL FIX: Eager load the field_mappings relationship to prevent async DetachedInstanceError
    stmt = select(RoutingRule).options(selectinload(RoutingRule.field_mappings)).order_by(RoutingRule.priority)
    rules = (await session.exec(stmt)).all()

    # Fetch dynamic Jira projects for the dropdown
    jira_client = JiraClient()
    # 1. Ensure you have the DomainConfig fetched
    config_stmt = select(DomainConfig).where(DomainConfig.domain_name == "pf_jira")
    config = (await session.exec(config_stmt)).first()

    # 2. Extract the field_id from config or use the migration default
    field_id = config.jira_pf_task_id_custom_field if config else "customfield_10048"

    # 3. Pass the argument to the client
    try:
        jira_projects = await jira_client.get_all_projects()
        jira_task_types = await jira_client.get_task_type_options(field_id)
        issuetype_map = await jira_client.get_issue_type_map()
    finally:
        await jira_client.close()

    return templates.TemplateResponse(
        "rules.html",
        {
            "request": request,
            "user": user,
            "routing_rules": rules,
            "jira_projects": jira_projects,
            "jira_task_types": jira_task_types,
            "issuetype_map": issuetype_map,
        },
    )


@router.post("/rules/routing", response_class=HTMLResponse)
async def add_routing_rule(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: dict[str, Any] = Depends(require_pf_jira_admin),
) -> HTMLResponse:
    """Creates a new priority-based routing rule with normalized dynamic field mappings."""
    form_data = await request.form()

    new_rule = RoutingRule(
        priority=int(form_data.get("priority", 100)),
        action=RoutingAction(form_data.get("action", "SYNC")),
        is_active=form_data.get("is_active") == "on",
        condition_assignee_pattern=form_data.get("condition_assignee_pattern", "").strip() or None,
        condition_title_keyword=form_data.get("condition_title_keyword", "").strip() or None,
        target_jira_project=form_data.get("target_jira_project", "").strip() or None,
    )

    # 1. Explicitly extract and map the reference issuetype required by the resolver
    reference_issuetype = form_data.get("reference_issuetype", "").strip()
    if reference_issuetype:
        new_rule.field_mappings.append(
            RuleFieldMapping(
                jira_field_id="issuetype", source_type=MappingSourceType.STATIC, source_value=reference_issuetype
            )
        )

    # 2. Extract dynamically injected fields and cast source vectors
    for key, value in form_data.items():
        if key.startswith("mapping_") and value:
            jira_field_id = key.replace("mapping_", "", 1)
            val_str = str(value).strip()

            if not val_str:
                continue

            source_type = MappingSourceType.PF_PAYLOAD if val_str.startswith("$.") else MappingSourceType.STATIC

            new_rule.field_mappings.append(
                RuleFieldMapping(jira_field_id=jira_field_id, source_type=source_type, source_value=val_str)
            )

    session.add(new_rule)
    await session.commit()

    # Eager load mappings to prevent DetachedInstanceError in the Jinja2 template
    stmt = select(RoutingRule).options(selectinload(RoutingRule.field_mappings)).order_by(RoutingRule.priority)
    rules = (await session.exec(stmt)).all()
    jira_client = JiraClient()
    try:
        issuetype_map = await jira_client.get_issue_type_map()
    except Exception:
        issuetype_map = {}
    finally:
        await jira_client.close()

    return templates.TemplateResponse(
        "partials/_routing_rules_tbody.html",
        {"request": request, "routing_rules": rules, "user": user, "issuetype_map": issuetype_map},
    )


def _parse_jira_schema_fields(schema: dict[str, Any]) -> tuple[list[tuple[str, Any]], list[tuple[str, Any]]]:
    """Helper to separate and filter schema fields into required and optional lists."""
    required_fields = []
    optional_fields = []
    exclude_ids = {"project", "issuetype", "attachment", "summary", "duedate", "description"}
    exclude_names = {"Start date", "Due date"}

    for field_id, meta in schema.items():
        if field_id in exclude_ids or meta.get("name") in exclude_names:
            continue
        if field_id == "reporter":
            meta["required"] = False

        if meta.get("required"):
            required_fields.append((field_id, meta))
        else:
            optional_fields.append((field_id, meta))

    return required_fields, optional_fields


@router.get("/rules/routing/{rule_id}/edit", response_class=HTMLResponse)
async def edit_routing_rule_modal(
    request: Request,
    rule_id: int,
    session: AsyncSession = Depends(get_session),
    user: dict[str, Any] = Depends(require_pf_jira_admin),
) -> HTMLResponse:
    """Fetches a specific routing rule and computes the live Jira schema for state hydration."""
    stmt = select(RoutingRule).where(RoutingRule.id == rule_id).options(selectinload(RoutingRule.field_mappings))
    rule = (await session.exec(stmt)).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Routing rule not found.")

    jira_client = JiraClient()
    redis_pool = getattr(request.app.state, "arq_pool", None)
    resolver = FieldDataResolver(jira_client, redis_pool)

    required_fields = []
    optional_fields = []
    jira_projects = []
    current_project_issuetypes = []  # <-- Initialize new list

    existing_mappings = {m.jira_field_id: m.source_value for m in rule.field_mappings}
    current_issuetype = existing_mappings.get("issuetype", "")

    try:
        jira_projects = await jira_client.get_all_projects()
        issuetype_map = await jira_client.get_issue_type_map()

        if rule.target_jira_project:
            # 1. Eagerly fetch the valid issue types for this specific project
            try:
                resp = await jira_client.client.get(f"/rest/api/3/project/{rule.target_jira_project}")
                resp.raise_for_status()
                current_project_issuetypes = [
                    it for it in resp.json().get("issueTypes", []) if not it.get("subtask", False)
                ]
            except Exception as e:
                logger.error(f"Failed to fetch issue types for project {rule.target_jira_project}: {e}")

            # 2. Pre-flight the schema if issuetype is already known
            if current_issuetype:
                schema = await resolver._get_createmeta(rule.target_jira_project, current_issuetype)
                required_fields, optional_fields = _parse_jira_schema_fields(schema)

    except Exception as e:
        logger.error(f"Failed to load schema for edit modal: {e}")
    finally:
        await jira_client.close()

    return templates.TemplateResponse(
        "partials/_rule_form_modal.html",
        {
            "request": request,
            "rule": rule,
            "jira_projects": jira_projects,
            "current_issuetype": current_issuetype,
            "current_issuetype_name": issuetype_map.get(current_issuetype, current_issuetype),
            "current_project_issuetypes": current_project_issuetypes,  # <-- Inject into context
            "existing_mappings": existing_mappings,
            "required_fields": required_fields,
            "optional_fields": optional_fields,
        },
    )


@router.post("/rules/routing/{rule_id}", response_class=HTMLResponse)
async def update_routing_rule(
    request: Request,
    rule_id: int,
    session: AsyncSession = Depends(get_session),
    user: dict[str, Any] = Depends(require_pf_jira_admin),
) -> HTMLResponse:
    """Updates a routing rule, executing an atomic replacement of all associated field mappings."""
    stmt = select(RoutingRule).where(RoutingRule.id == rule_id).options(selectinload(RoutingRule.field_mappings))
    rule = (await session.exec(stmt)).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Routing rule not found.")

    form_data = await request.form()

    rule.priority = int(form_data.get("priority", 100))
    rule.action = RoutingAction(form_data.get("action", "SYNC"))
    rule.is_active = form_data.get("is_active") == "on"
    rule.condition_assignee_pattern = form_data.get("condition_assignee_pattern", "").strip() or None
    rule.condition_title_keyword = form_data.get("condition_title_keyword", "").strip() or None
    rule.target_jira_project = form_data.get("target_jira_project", "").strip() or None

    # Clear existing mappings. SQLModel `cascade="all, delete-orphan"` ensures DB integrity.
    rule.field_mappings.clear()

    reference_issuetype = form_data.get("reference_issuetype", "").strip()
    if reference_issuetype:
        rule.field_mappings.append(
            RuleFieldMapping(
                jira_field_id="issuetype", source_type=MappingSourceType.STATIC, source_value=reference_issuetype
            )
        )

    for key, value in form_data.items():
        if key.startswith("mapping_") and value:
            jira_field_id = key.replace("mapping_", "", 1)
            val_str = str(value).strip()

            if not val_str:
                continue

            source_type = MappingSourceType.PF_PAYLOAD if val_str.startswith("$.") else MappingSourceType.STATIC

            rule.field_mappings.append(
                RuleFieldMapping(jira_field_id=jira_field_id, source_type=source_type, source_value=val_str)
            )

    session.add(rule)
    await session.commit()

    stmt_all = select(RoutingRule).options(selectinload(RoutingRule.field_mappings)).order_by(RoutingRule.priority)
    rules = (await session.exec(stmt_all)).all()
    jira_client = JiraClient()
    try:
        issuetype_map = await jira_client.get_issue_type_map()
    except Exception:
        issuetype_map = {}
    finally:
        await jira_client.close()

    return templates.TemplateResponse(
        "partials/_routing_rules_tbody.html",
        {"request": request, "routing_rules": rules, "user": user, "issuetype_map": issuetype_map},
    )


@router.delete("/rules/routing/{rule_id}", status_code=status.HTTP_200_OK)
async def delete_routing_rule(
    rule_id: int,
    session: AsyncSession = Depends(get_session),
    user: dict[str, Any] = Depends(require_pf_jira_admin),
) -> str:
    """Deletes a specific routing rule.

    Args:
        rule_id: The primary key of the rule to delete.
        session: The asynchronous database session.
        user: The authenticated user context enforcing mutation privileges.

    Returns:
        str: An empty string instructing HTMX to swap the row out of the DOM.
    """
    rule = await session.get(RoutingRule, rule_id)
    if rule:
        await session.delete(rule)
        await session.commit()
    return ""


@router.get("/users", response_class=HTMLResponse)
async def manage_users_dashboard(
    request: Request,
    user: dict[str, Any] = Depends(require_system_admin),
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    """Renders the User Management dashboard."""
    system_users = (await session.exec(select(User).order_by(User.id))).all()
    return templates.TemplateResponse("users.html", {"request": request, "user": user, "system_users": system_users})


@router.post("/users/{target_id}", response_class=HTMLResponse)
async def update_user_access(
    request: Request,
    target_id: int,
    form: UserAccessForm = Depends(),
    user: dict[str, Any] = Depends(require_system_admin),
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    """HTMX endpoint to update a user's role and activation status inline.

    Args:
        request: The incoming HTTP request.
        target_id: The primary key of the user being modified.
        form: The injected form payload containing the new role and status.
        user: The authenticated system administrator context.
        session: The asynchronous database session.

    Returns:
        HTMLResponse: An HTMX toast notification indicating success or failure.

    Raises:
        HTTPException: A 404 Not Found error if the target user does not exist.
    """
    target_user = await session.get(User, target_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    if target_user.id == user.get("id") and not form.is_active:
        return templates.TemplateResponse(
            "partials/_toast.html",
            {
                "request": request,
                "level": "danger",
                "message": "Cannot deactivate your own session.",
            },
        )

    target_user.is_active = form.is_active
    target_user.role = UserRole(form.role)
    session.add(target_user)
    await session.commit()

    return templates.TemplateResponse(
        "partials/_toast.html",
        {"request": request, "level": "success", "message": f"Updated {target_user.email}"},
    )


@router.post("/users", response_class=Response)
async def pre_provision_user(
    request: Request,
    form: UserProvisionForm = Depends(),
    user: dict[str, Any] = Depends(require_system_admin),
    session: AsyncSession = Depends(get_session),
) -> Response:
    """Proactively whitelists a user before their first SSO login.

    Args:
        request: The incoming HTTP request.
        form: The injected form payload containing the email and role to provision.
        user: The authenticated system administrator context.
        session: The asynchronous database session.

    Returns:
        Response: An HTMX-compatible response triggering a page refresh or a warning toast.
    """
    existing = (await session.exec(select(User).where(User.email == form.email))).first()
    if existing:
        return templates.TemplateResponse(
            "partials/_toast.html",
            {
                "request": request,
                "level": "warning",
                "message": f"User {form.email} is already registered.",
            },
        )

    new_user = User(
        email=form.email.lower(),
        full_name="Pending SSO Login",
        is_active=True,
        role=UserRole(form.role),
    )
    session.add(new_user)
    await session.commit()

    response = Response(status_code=status.HTTP_200_OK)
    response.headers["HX-Refresh"] = "true"
    return response


@router.delete("/users/{target_id}", status_code=status.HTTP_200_OK)
async def delete_user(
    target_id: int,
    session: AsyncSession = Depends(get_session),
    user: dict[str, Any] = Depends(require_system_admin),
) -> str:
    """Hard-deletes a user from the system."""
    target_user = await session.get(User, target_id)

    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Safeguard: Prevent self-deletion
    if target_user.id == user.get("id"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot delete your own active session.")

    await session.delete(target_user)
    await session.commit()

    # Returning an empty string instructs HTMX to swap the row into oblivion
    return ""


@router.get("/audit", response_class=HTMLResponse)
async def audit_dashboard(
    request: Request,
    params: AuditQueryParams = Depends(),
    session: AsyncSession = Depends(get_session),
    user: dict[str, Any] = Depends(get_current_admin_user),
) -> HTMLResponse:
    """Renders the paginated and searchable Sync Audit Log.

    Args:
        request: The incoming HTTP request.
        params: The injected query parameters containing search, filter, and pagination states.
        session: The asynchronous database session.
        user: The authenticated user context.

    Returns:
        HTMLResponse: Either the full dashboard or the HTMX table fragment.
    """
    page_size = 50
    offset = (params.page - 1) * page_size

    statement = select(SyncAuditLog).order_by(desc(SyncAuditLog.timestamp))

    if params.query:
        search_term = f"%{params.query}%"
        statement = statement.where(
            or_(
                SyncAuditLog.jira_issue_key.like(search_term),
                SyncAuditLog.pf_task_id.like(search_term),
                SyncAuditLog.details.like(search_term),
            )
        )

    if params.operation:
        statement = statement.where(SyncAuditLog.operation == params.operation)

    statement = statement.offset(offset).limit(page_size + 1)
    results = (await session.exec(statement)).all()

    has_next = len(results) > page_size
    logs = results[:page_size]

    context = {
        "request": request,
        "user": user,
        "logs": logs,
        "page": params.page,
        "has_next": has_next,
        "query": params.query or "",
        "pf_url": settings.PF_URL,
    }

    if request.headers.get("HX-Request"):
        return templates.TemplateResponse("partials/_audit_tbody.html", context)

    return templates.TemplateResponse("audit.html", context)


@router.get("/rules/project/{project_key}/validate", response_class=HTMLResponse)
async def validate_project_rule(
    request: Request, project_key: str, user: dict[str, Any] = Depends(require_pf_jira_admin)
) -> HTMLResponse:
    """Proactively verifies Jira token permissions for a specific routing destination.

    Args:
        request: The incoming HTTP request.
        project_key: The targeted Jira project key.
        user: The authenticated user context.

    Returns:
        HTMLResponse: An HTMX-compatible toast notification.
    """
    jira_client = JiraClient()
    try:
        is_valid, missing = await jira_client.validate_project_permissions(project_key)
    except httpx.HTTPStatusError as e:
        status_code = e.response.status_code
        detail = "Project not found" if status_code == status.HTTP_404_NOT_FOUND else f"HTTP {status_code}"
        return templates.TemplateResponse(
            "partials/_toast.html", {"request": request, "level": "danger", "message": f"Validation failed: {detail}"}
        )
    finally:
        await jira_client.close()

    if is_valid:
        msg = f"Token is fully authorized for project {project_key}."
        level = "success"
    else:
        msg = f"Missing permissions in {project_key}: {', '.join(missing)}"
        level = "warning"

    return templates.TemplateResponse("partials/_toast.html", {"request": request, "level": level, "message": msg})


@router.post("/rules/validate/start", response_class=HTMLResponse)
async def start_rule_validation(
    request: Request, user: dict[str, Any] = Depends(require_pf_jira_admin)
) -> HTMLResponse:
    """Enqueues the validation job and returns the initial polling UI."""
    # Set the initial state in Redis to prevent a race condition with the UI poller
    redis_client = redis.from_url(settings.REDIS_URL)
    await redis_client.setex("pf_jira:validation_report", 300, json.dumps({"status": "processing"}))
    await redis_client.aclose()

    # CRITICAL FIX: Use the bound application pool instead of creating a transient one
    arq_pool = getattr(request.app.state, "arq_pool", None)
    if arq_pool:
        await arq_pool.enqueue_job("validate_routing_rules_task", _queue_name="pf_jira_queue")

    return templates.TemplateResponse("partials/_validation_status.html", {"request": request, "status": "processing"})


@router.get("/rules/validate/status", response_class=HTMLResponse)
async def get_validation_status(
    request: Request, user: dict[str, Any] = Depends(require_pf_jira_admin)
) -> HTMLResponse:
    """Polled by HTMX to check the background validation status."""
    redis_client = redis.from_url(settings.REDIS_URL)
    raw_data = await redis_client.get("pf_jira:validation_report")
    await redis_client.aclose()

    if not raw_data:
        # Fallback if Redis key expires or disappears
        return HTMLResponse("")

    data = json.loads(raw_data)
    return templates.TemplateResponse(
        "partials/_validation_status.html",
        {
            "request": request,
            "status": data.get("status"),
            "details": data.get("details", []),
            "error": data.get("error"),
        },
    )


@router.get("/rules/schema/issuetypes", response_class=HTMLResponse)
async def get_project_issuetypes(request: Request, target_jira_project: str) -> HTMLResponse:
    jira_client = JiraClient()
    try:
        resp = await jira_client.client.get(f"/rest/api/3/project/{target_jira_project}")
        resp.raise_for_status()
        issue_types = resp.json().get("issueTypes", [])

        html = '<option value="" disabled selected>Select Reference Issue Type...</option>'
        for it in issue_types:
            if not it.get("subtask", False):
                html += f'<option value="{it["id"]}">{it["name"]}</option>'

        # Tom Select maintains an internal cache. We must explicitly clear it
        # using its JS API when the project changes, rather than just syncing.
        html += """
        <script>
            (function() {
                var el = document.getElementById('issuetype-select');
                if (el && el.tomselect) {
                    el.tomselect.clearOptions();
                    el.tomselect.sync();
                }
            })();
        </script>
        """
        return HTMLResponse(content=html)
    except Exception as e:
        return HTMLResponse(content=f"<option disabled>Error loading types: {e}</option>")
    finally:
        await jira_client.close()


@router.get("/rules/schema/fields", response_class=HTMLResponse)
async def get_schema_fields(request: Request, target_jira_project: str, reference_issuetype: str) -> HTMLResponse:
    jira_client = JiraClient()
    redis_pool = request.app.state.arq_pool
    resolver = FieldDataResolver(jira_client, redis_pool)

    try:
        schema = await resolver._get_createmeta(target_jira_project, reference_issuetype)
        required_fields, optional_fields = _parse_jira_schema_fields(schema)

        return templates.TemplateResponse(
            "partials/_schema_fields.html",
            {"request": request, "required_fields": required_fields, "optional_fields": optional_fields},
        )
    except Exception as e:
        return HTMLResponse(content=f'<div class="notification is-danger">Failed to load schema: {e}</div>')
    finally:
        await jira_client.close()


@router.get("/rules/routing/new", response_class=HTMLResponse)
async def new_routing_rule_modal(
    request: Request,
    user: dict[str, Any] = Depends(get_current_admin_user),  # Adjust dependency if using require_pf_jira_admin
) -> HTMLResponse:
    """Provides an unhydrated modal for creating a new Routing Rule."""
    jira_client = JiraClient()
    try:
        jira_projects = await jira_client.get_all_projects()
    except Exception as e:
        logger.error(f"Failed to fetch Jira projects for new rule modal: {e}")
        jira_projects = []
    finally:
        await jira_client.close()

    return templates.TemplateResponse(
        "partials/_rule_form_modal.html",
        {
            "request": request,
            "rule": None,
            "jira_projects": jira_projects,
            "current_issuetype": None,
            "existing_mappings": {},
            "required_fields": [],
            "optional_fields": [],
        },
    )
