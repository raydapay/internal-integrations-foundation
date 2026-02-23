import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, ClassVar

import httpx
import psutil
import redis.asyncio as redis
from arq import cron
from arq.connections import RedisSettings
from arq.worker import Retry
from fastapi import status
from loguru import logger
from redis.exceptions import LockError
from sqlalchemy import Integer, cast, func
from sqlmodel import SQLModel, select
from sqlmodel.ext.asyncio.session import AsyncSession

from src.config.settings import settings
from src.core.clients import JiraClient, PeopleForceClient
from src.core.database import async_session_maker, engine
from src.core.logger import configure_logging
from src.core.notifications import notify
from src.domain.pf_jira.mapping import (
    JIRA_CUSTOM_FIELD_START_DATE,
    build_adf_description,
    evaluate_routing_rules,
)
from src.domain.pf_jira.models import DomainConfig, RoutingAction, RoutingRule, SyncAuditLog, SyncOperation, SyncState


def _compute_hash(data: dict[str, Any]) -> str:
    """Computes a stable SHA-256 hash of a dictionary representation."""
    serialized = json.dumps(data, sort_keys=True).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


async def _evaluate_polling_state(
    redis_client: redis.Redis, is_manual_trigger: bool
) -> tuple[dict[str, str] | None, DomainConfig | None]:
    """Evaluates the Tick/Yield infrastructure state for the polling loop.

    Args:
        redis_client: The active async Redis connection pool.
        is_manual_trigger: Boolean flag indicating if the UI forced a delta-sync.

    Returns:
        tuple[dict[str, str] | None, DomainConfig | None]:
            - If the worker should yield, returns the yield status payload and None.
            - If the worker should proceed, returns None and the active DomainConfig.
    """
    async with async_session_maker() as session:
        stmt = select(DomainConfig).where(DomainConfig.domain_name == "pf_jira")
        config = (await session.exec(stmt)).first()

    if not config:
        logger.error("DomainConfig missing. Yielding execution.")
        return {"status": "yield_missing_config"}, None

    if not config.is_active and not is_manual_trigger:
        logger.debug("Domain pf_jira is globally disabled. Yielding.")
        return {"status": "yield_inactive"}, None

    last_run_key = "pf_jira:last_sync_timestamp"
    if not is_manual_trigger:
        last_run_raw = await redis_client.get(last_run_key)
        if last_run_raw:
            last_run_time = float(last_run_raw)
            now = datetime.now(UTC).timestamp()
            if (now - last_run_time) < config.polling_interval_seconds:
                # Polling interval not met yet, yield silently
                return {"status": "yield_interval_not_met"}, None

    # Register the execution time lock immediately to prevent concurrent ticks
    await redis_client.set(last_run_key, datetime.now(UTC).timestamp())

    return None, config


async def _calculate_sync_watermark(session: AsyncSession) -> int:
    """Determines the baseline PeopleForce task ID to establish a delta-polling boundary.

    Args:
        session: The active asynchronous database session.

    Returns:
        int: The lowest unresolved Task ID, falling back to the highest known ID, or 0.
    """
    stmt_min_open = select(func.min(cast(SyncState.pf_entity_id, Integer))).where(
        SyncState.pf_entity_type == "task", SyncState.is_completed.is_(False)
    )
    watermark_id = (await session.exec(stmt_min_open)).first()

    if watermark_id is None:
        stmt_max_all = select(func.max(cast(SyncState.pf_entity_id, Integer))).where(SyncState.pf_entity_type == "task")
        watermark_id = (await session.exec(stmt_max_all)).first()

    return watermark_id or 0


async def _resolve_identities_and_routing(
    session: AsyncSession, jira_client: JiraClient, task: dict[str, Any]
) -> dict[str, Any]:
    """Evaluates routing rules and resolves Jira account identities via the Atlassian API.

    Args:
        session: The active asynchronous database session.
        jira_client: The active Jira HTTP client.
        task: The raw PeopleForce task payload.

    Returns:
        dict[str, Any]: Consolidated dictionary of routing targets, labels, and resolved Jira account IDs.
    """
    routing = await evaluate_routing_rules(session, task)

    assignee_email = task.get("assigned_to", {}).get("email")

    # Apply Firewall overrides or fallback to PF defaults
    resolved_assignee_email = routing["assignee_email"] or assignee_email
    resolved_reporter_email = routing["reporter_email"] or resolved_assignee_email

    # Hit Atlassian API for exact account mappings
    assignee_id = await jira_client.get_account_id_by_email(resolved_assignee_email)
    reporter_id = await jira_client.get_account_id_by_email(resolved_reporter_email)

    return {
        "action": routing["action"],
        "target_project": routing["project"],
        "task_type": routing["task_type"],
        "target_labels": ["PeopleForce"] + routing["labels"],
        "assignee_id": assignee_id,
        "reporter_id": reporter_id,
        "resolved_assignee_email": resolved_assignee_email,
        "resolved_reporter_email": resolved_reporter_email,
    }


def _build_jira_create_payload(
    task: dict[str, Any], routing_data: dict[str, Any], config: DomainConfig, summary: str
) -> dict[str, Any]:
    """Constructs the Atlassian API JSON payload for creating a new Jira issue.

    Args:
        task: The raw PeopleForce task payload.
        routing_data: The resolved firewall identities and target configurations.
        config: The active domain configuration.
        summary: The pre-computed Jira issue summary string.

    Returns:
        dict[str, Any]: The finalized JSON-serializable dictionary for issue creation.
    """
    task_id = str(task.get("id"))
    starts_on = task.get("starts_on")
    ends_on = task.get("ends_on")

    payload = {
        "fields": {
            "project": {"key": routing_data["target_project"]},
            "summary": summary,
            "description": build_adf_description(task),
            "issuetype": {"name": "Task"},
            "labels": routing_data["target_labels"],
        },
        "properties": [{"key": "pf_sync_metadata", "value": {"pf_task_id": task_id}}],
    }

    if routing_data["assignee_id"]:
        payload["fields"]["assignee"] = {"accountId": routing_data["assignee_id"]}
    elif config.jira_fallback_account_id:
        payload["fields"]["assignee"] = {"accountId": config.jira_fallback_account_id}

    if routing_data["reporter_id"]:
        payload["fields"]["reporter"] = {"accountId": routing_data["reporter_id"]}

    if routing_data["task_type"] and config.jira_pf_task_id_custom_field:
        payload["fields"][config.jira_pf_task_id_custom_field] = {"value": routing_data["task_type"]}

    if ends_on:
        payload["fields"]["duedate"] = ends_on
    if starts_on:
        payload["fields"][JIRA_CUSTOM_FIELD_START_DATE] = starts_on

    return payload


def _build_jira_update_payload(
    task: dict[str, Any], routing_data: dict[str, Any], config: DomainConfig, summary: str
) -> dict[str, Any]:
    """Constructs the Atlassian API JSON payload for mutating an existing Jira issue.

    Args:
        task: The raw PeopleForce task payload.
        routing_data: The resolved firewall identities and target configurations.
        config: The active domain configuration.
        summary: The pre-computed Jira issue summary string.

    Returns:
        dict[str, Any]: The finalized JSON-serializable dictionary for issue updating.
    """
    starts_on = task.get("starts_on")
    ends_on = task.get("ends_on")

    payload = {
        "fields": {
            "summary": summary,
            "description": build_adf_description(task),
            "labels": routing_data["target_labels"],
        }
    }

    if routing_data["assignee_id"]:
        payload["fields"]["assignee"] = {"accountId": routing_data["assignee_id"]}
    else:
        payload["fields"]["assignee"] = None  # Explicitly unassign if identity mapping fails on update

    if routing_data["reporter_id"]:
        payload["fields"]["reporter"] = {"accountId": routing_data["reporter_id"]}

    if routing_data["task_type"] and config.jira_pf_task_id_custom_field:
        payload["fields"][config.jira_pf_task_id_custom_field] = {"value": routing_data["task_type"]}

    if not routing_data["assignee_id"] and config.jira_fallback_account_id:
        payload["fields"]["assignee"] = {"accountId": config.jira_fallback_account_id}

    if ends_on:
        payload["fields"]["duedate"] = ends_on
    if starts_on:
        payload["fields"][JIRA_CUSTOM_FIELD_START_DATE] = starts_on

    return payload


async def _execute_safe_jira_update(
    session: AsyncSession,
    jira_client: JiraClient,
    state_record: SyncState,
    update_payload: dict[str, Any],
) -> bool:
    """Executes a Jira update and gracefully handles 404 Ghost Records.

    Args:
        session: The asynchronous database session.
        jira_client: The initialized Jira API client.
        state_record: The local synchronization state record.
        update_payload: The computed Jira update payload.

    Returns:
        bool: True if the update succeeded, False if a 404 occurred and state was purged.

    Raises:
        httpx.HTTPStatusError: For any non-404 HTTP errors, triggering ARQ retries.
    """
    issue_key = state_record.jira_issue_key
    task_id = state_record.pf_entity_id

    try:
        await jira_client.update_issue(issue_key, update_payload)
        return True
    except httpx.HTTPStatusError as e:
        if e.response.status_code == status.HTTP_404_NOT_FOUND:
            logger.warning(
                f"Jira issue {issue_key} (PF Task {task_id}) was deleted externally (404). Purging local state."
            )
            await session.delete(state_record)
            session.add(
                SyncAuditLog(
                    pf_task_id=task_id,
                    jira_issue_key=issue_key,
                    operation=SyncOperation.ERROR,
                    details=json.dumps(
                        {"error": "Jira 404 Not Found. Local state purged to force recreation next cycle."},
                        ensure_ascii=False,
                    ),
                )
            )
            await session.commit()
            return False
        raise


@dataclass
class SyncContext:
    """Encapsulates dependencies and state for single-task processing."""

    session: AsyncSession
    jira_client: JiraClient
    redis_client: redis.Redis
    config: DomainConfig
    stats: dict[str, int]
    cutoff_date: datetime | None
    job_id: str


@dataclass
class TaskContext:
    """Encapsulates the parsed state and pre-computed values of a single PeopleForce task."""

    raw: dict[str, Any]
    id: str
    is_completed: bool
    hash: str
    summary: str


def _is_task_historical(task: dict[str, Any], cutoff_date: datetime, task_id: str) -> bool:
    """Evaluates whether a task falls outside the active synchronization window.

    Args:
        task: The raw PeopleForce task payload.
        cutoff_date: The baseline datetime threshold.
        task_id: The extracted Task ID for logging.

    Returns:
        bool: True if the task was created before the cutoff, False otherwise.
    """
    created_at_str = task.get("created_at")
    if not created_at_str:
        return False

    try:
        created_at = datetime.fromisoformat(created_at_str)
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=UTC)
        return created_at < cutoff_date
    except (ValueError, TypeError):
        logger.warning(f"Failed to parse created_at '{created_at_str}' for PF Task {task_id}. Evaluating for sync.")
        return False


async def _handle_issue_creation(sync_ctx: SyncContext, task_ctx: TaskContext, routing_data: dict[str, Any]) -> None:
    """Executes the complete lifecycle for generating a new Jira issue and recording state.

    Args:
        sync_ctx: Global synchronization dependencies and metrics.
        task_ctx: Parsed context for the current PeopleForce task.
        routing_data: Firewall and identity resolution outputs.
    """
    task_logger = logger.bind(pf_task_id=task_ctx.id, job_id=sync_ctx.job_id)

    jira_payload = _build_jira_create_payload(task_ctx.raw, routing_data, sync_ctx.config, task_ctx.summary)
    task_logger.debug(f"Computed Jira Payload: {json.dumps(jira_payload)}")

    issue = await sync_ctx.jira_client.create_issue(jira_payload)
    issue_key = issue["key"]

    new_state = SyncState(
        pf_entity_type="task",
        pf_entity_id=task_ctx.id,
        jira_issue_key=issue_key,
        jira_issue_id=issue["id"],
        last_sync_hash=task_ctx.hash,
        is_completed=task_ctx.is_completed,
    )
    sync_ctx.session.add(new_state)

    sync_ctx.session.add(
        SyncAuditLog(
            pf_task_id=task_ctx.id,
            jira_issue_key=issue_key,
            operation=SyncOperation.CREATE,
            details=json.dumps(
                {
                    "project": routing_data["target_project"],
                    "assignee_email_resolved": routing_data["resolved_assignee_email"],
                    "reporter_email_resolved": routing_data["resolved_reporter_email"],
                    "task_type": routing_data["task_type"],
                    "labels": routing_data["target_labels"],
                    "summary_injected": task_ctx.summary,
                },
                indent=2,
                ensure_ascii=False,
            ),
        )
    )
    sync_ctx.stats["created"] += 1
    task_logger.info(f"Created Jira issue {issue_key}")

    if task_ctx.is_completed:
        await sync_ctx.jira_client.transition_issue_to_done(issue_key)
        await sync_ctx.jira_client.add_comment(
            issue_key,
            "This issue was automatically closed because the corresponding task was marked "
            "as completed in PeopleForce.",
        )
        task_logger.info(f"Transitioned {issue_key} to Done upon creation.")


async def _handle_issue_update(
    sync_ctx: SyncContext, task_ctx: TaskContext, routing_data: dict[str, Any], state_record: SyncState
) -> None:
    """Executes the mutation lifecycle for an existing Jira issue, handling state reconciliation.

    Args:
        sync_ctx: Global synchronization dependencies and metrics.
        task_ctx: Parsed context for the current PeopleForce task.
        routing_data: Firewall and identity resolution outputs.
        state_record: The previously tracked local database state.
    """
    task_logger = logger.bind(pf_task_id=task_ctx.id, job_id=sync_ctx.job_id)
    issue_key = state_record.jira_issue_key

    update_payload = _build_jira_update_payload(task_ctx.raw, routing_data, sync_ctx.config, task_ctx.summary)
    task_logger.debug(f"Computed Update Payload: {json.dumps(update_payload)}")

    update_success = await _execute_safe_jira_update(
        sync_ctx.session, sync_ctx.jira_client, state_record, update_payload
    )
    if not update_success:
        return  # State was purged (404), yield and let it recreate on next tick

    if task_ctx.is_completed:
        await sync_ctx.jira_client.transition_issue_to_done(issue_key)
        task_logger.info(f"Transitioned {issue_key} to Done during update.")

    state_record.last_sync_hash = task_ctx.hash
    state_record.last_updated_at = datetime.utcnow()
    state_record.is_completed = task_ctx.is_completed
    sync_ctx.session.add(state_record)

    sync_ctx.session.add(
        SyncAuditLog(
            pf_task_id=task_ctx.id,
            jira_issue_key=issue_key,
            operation=SyncOperation.UPDATE,
            details=json.dumps(
                {
                    "assignee_email_resolved": routing_data["resolved_assignee_email"],
                    "reporter_email_resolved": routing_data["resolved_reporter_email"],
                    "task_type_resolved": routing_data["task_type"],
                    "labels_resolved": routing_data["target_labels"],
                    "completed_status_triggered": task_ctx.is_completed,
                },
                ensure_ascii=False,
            ),
        )
    )
    sync_ctx.stats["updated"] += 1
    task_logger.info(f"Updated Jira issue {issue_key}")


async def _process_single_task(task: dict[str, Any], ctx: SyncContext) -> None:
    """Evaluates and synchronizes a single PeopleForce task against the Jira state matrix.

    Args:
        task: The raw dictionary payload from the PeopleForce API.
        ctx: The global synchronization context object.
    """
    task_id = str(task.get("id"))
    task_logger = logger.bind(pf_task_id=task_id, job_id=ctx.job_id)

    if ctx.cutoff_date and _is_task_historical(task, ctx.cutoff_date, task_id):
        ctx.stats["skipped"] += 1
        return

    # Extract Base Task Context
    raw_title = task.get("title", f"Task {task_id}")
    assoc_name = task.get("associated_to", {}).get("full_name")

    task_ctx = TaskContext(
        raw=task,
        id=task_id,
        is_completed=task.get("completed", False),
        hash=_compute_hash(task),
        summary=f"[PF] {raw_title} - {assoc_name}" if assoc_name else f"[PF] {raw_title}",
    )

    lock_key = f"lock:pf_jira:task:{task_id}"

    try:
        async with ctx.redis_client.lock(lock_key, timeout=10.0, blocking_timeout=2.0):
            statement = select(SyncState).where(SyncState.pf_entity_type == "task", SyncState.pf_entity_id == task_id)
            state_record = (await ctx.session.exec(statement)).first()

            routing_data = await _resolve_identities_and_routing(ctx.session, ctx.jira_client, task)

            if routing_data["action"] == RoutingAction.DROP:
                task_logger.debug(f"Task {task_id} dropped by firewall routing rule.")
                ctx.stats["skipped"] += 1
                return

            if not state_record:
                await _handle_issue_creation(ctx, task_ctx, routing_data)
            elif state_record.last_sync_hash != task_ctx.hash:
                await _handle_issue_update(ctx, task_ctx, routing_data, state_record)
            else:
                ctx.stats["skipped"] += 1
                task_logger.debug(
                    f"Skipped (No Delta): Payload hash {task_ctx.hash} exactly matches "
                    "the state stored in the database."
                )

            await ctx.session.commit()

    except LockError:
        task_logger.warning("Task locked by concurrent worker process. Yielding.")


async def sync_pf_to_jira_task(ctx: dict[Any, Any], payload: dict[str, Any] | None = None) -> dict[str, Any]:
    """Polls PeopleForce tasks, computes state deltas, and synchronizes mutations to Jira.

    Implements a Tick/Yield pattern driven by DomainConfig to allow runtime mutability
    without worker restarts.
    """
    payload = payload or {}
    job_id = ctx.get("job_id", "unknown")
    redis_client = ctx["redis"]
    is_manual_trigger = payload.get("manual_trigger", False)

    # 1. Tick/Yield Pre-Flight Evaluation
    yield_status, config = await _evaluate_polling_state(redis_client, is_manual_trigger)
    if yield_status or not config:
        return yield_status or {"status": "yield_error"}

    # --- Core Execution Begins ---
    pf_client = PeopleForceClient()
    jira_client = JiraClient()
    stats = {"created": 0, "updated": 0, "skipped": 0, "status": "executed"}

    cutoff_date = settings.PF_SYNC_CREATED_AFTER
    if cutoff_date and cutoff_date.tzinfo is None:
        cutoff_date = cutoff_date.replace(tzinfo=UTC)

    # Encapsulate loop dependencies
    sync_ctx = SyncContext(
        session=None,  # Assigned inside the active context block
        jira_client=jira_client,
        redis_client=redis_client,
        config=config,
        stats=stats,
        cutoff_date=cutoff_date,
        job_id=job_id,
    )

    try:
        async with async_session_maker() as session:
            sync_ctx.session = session
            watermark_id = await _calculate_sync_watermark(session)
            tasks = await pf_client.get_tasks(watermark_id=watermark_id)

            for task in tasks:
                await _process_single_task(task, sync_ctx)

    except Exception as err:
        logger.exception("Catastrophic failure in state reconciliation loop.")

        # Dispatch the alert
        await notify(f"🔥 *Worker Crash* in `sync_pf_to_jira_task`:\n`{type(err).__name__}: {err!s}`")

        async with async_session_maker() as error_session:
            error_session.add(
                SyncAuditLog(
                    direction="System ➡️ Internal",
                    operation=SyncOperation.ERROR,
                    details=json.dumps(
                        {
                            "error_type": type(err).__name__,
                            "error_message": str(err),
                            "job_id": job_id,
                            "retry_count": ctx.get("job_try", 1),
                        },
                        ensure_ascii=False,
                    ),
                )
            )
            await error_session.commit()

        raise Retry(defer=ctx.get("job_try", 1) * 5) from err

    finally:
        await pf_client.close()
        await jira_client.close()

    return stats


async def sync_jira_to_pf_task(ctx: dict[Any, Any], issue_key: str) -> None:
    """Processes Jira completion webhooks and synchronizes state back to PeopleForce.

    Acquires a distributed Redis lock based on the underlying PeopleForce entity ID
    to prevent race conditions with the primary polling loop. Incorporates self-healing
    logic for Ghost Records (404 Not Found) in the upstream HRIS.

    Args:
        ctx: ARQ worker context containing the Redis connection pool.
        issue_key: The Jira issue key triggering the sync (e.g., 'HR-123').

    Raises:
        Retry: If a distributed lock cannot be acquired or recoverable network I/O fails.
    """
    job_id = ctx.get("job_id", "unknown")
    redis_client = ctx["redis"]
    pf_client = PeopleForceClient()

    task_logger = logger.bind(jira_issue_key=issue_key, job_id=job_id, direction="Jira ➡️ PF")

    try:
        async with async_session_maker() as session:
            stmt = select(SyncState).where(SyncState.jira_issue_key == issue_key)
            state_record = (await session.exec(stmt)).first()

            if not state_record:
                task_logger.warning("Unmapped issue transition. Ignoring webhook.")
                return

            if state_record.is_completed:
                task_logger.debug("Task already marked completed in database. Skipping.")
                return

            task_id = state_record.pf_entity_id
            lock_key = f"lock:pf_jira:task:{task_id}"

            try:
                async with redis_client.lock(lock_key, timeout=10.0, blocking_timeout=2.0):
                    state_record = await session.get(SyncState, state_record.id)
                    if not state_record or state_record.is_completed:
                        return

                    # --- Self-Healing 404 Intercept ---
                    try:
                        await pf_client.complete_task(task_id)
                    except httpx.HTTPStatusError as e:
                        if e.response.status_code == status.HTTP_404_NOT_FOUND:
                            task_logger.warning(
                                f"PeopleForce task {task_id} was deleted externally (404). "
                                "Purging local state to prevent retry deadlocks."
                            )
                            await session.delete(state_record)
                            session.add(
                                SyncAuditLog(
                                    direction="Jira ➡️ PF",
                                    pf_task_id=task_id,
                                    jira_issue_key=issue_key,
                                    operation=SyncOperation.ERROR,
                                    details=json.dumps(
                                        {
                                            "error": "PeopleForce 404 Not Found. Local state purged.",
                                            "action": "task_completion_aborted",
                                        },
                                        ensure_ascii=False,
                                    ),
                                )
                            )
                            await session.commit()
                            return  # Yield execution entirely

                        raise  # Re-raise 429s, 500s, etc., to trigger ARQ retry queue

                    # Local State Reconciliation
                    state_record.is_completed = True
                    state_record.last_updated_at = datetime.utcnow()
                    session.add(state_record)

                    session.add(
                        SyncAuditLog(
                            direction="Jira ➡️ PF",
                            pf_task_id=task_id,
                            jira_issue_key=issue_key,
                            operation=SyncOperation.UPDATE,
                            details=json.dumps(
                                {"action": "task_completed", "trigger": "jira_webhook"}, ensure_ascii=False
                            ),
                        )
                    )

                    await session.commit()
                    task_logger.info(f"Successfully closed PeopleForce task {task_id}.")

            except LockError as err:
                task_logger.warning("Record locked by concurrent polling worker. Yielding.")
                raise Retry(defer=ctx.get("job_try", 1) * 5) from err

    except Exception as err:
        if not isinstance(err, Retry):
            task_logger.exception("Failure processing Jira return vector.")
            raise Retry(defer=ctx.get("job_try", 1) * 5) from err
        raise
    finally:
        await pf_client.close()


async def validate_routing_rules_task(ctx: dict[Any, Any]) -> dict[str, Any]:
    """Validates configured Jira targets and identities against the live Atlassian API.

    Writes the resulting validation matrix to a transient Redis key for
    HTMX frontend polling.
    """
    redis_client = ctx["redis"]
    jira_client = JiraClient()

    try:
        async with async_session_maker() as session:
            statement = select(RoutingRule).where(RoutingRule.is_active)
            rules = (await session.exec(statement)).all()

        results = []

        # 1. Project Validation
        jira_projects = await jira_client.get_all_projects()
        valid_project_keys = {p["key"] for p in jira_projects}

        configured_projects = {r.target_jira_project for r in rules if r.target_jira_project}
        for proj in configured_projects:
            if proj in valid_project_keys:
                results.append({"project": f"Project: {proj}", "valid": True, "message": "OK"})
            else:
                results.append(
                    {
                        "project": f"Project: {proj}",
                        "valid": False,
                        "message": "Project Not Found or Missing Permissions",
                    }
                )

        # 2. Identity Validation (Overrides)
        # Extract unique emails across both assignee and reporter overrides
        configured_emails = {
            email for r in rules for email in (r.target_assignee_email, r.target_reporter_email) if email
        }

        for email in configured_emails:
            account_id = await jira_client.get_account_id_by_email(email)
            if account_id:
                results.append({"project": f"User: {email}", "valid": True, "message": "Account resolved"})
            else:
                results.append(
                    {"project": f"User: {email}", "valid": False, "message": "Unmapped email (Not found in Jira)"}
                )

        # 3. Task Type Validation (Strict List)
        # First, fetch the config to get the field ID
        async with async_session_maker() as session:
            stmt = select(DomainConfig).where(DomainConfig.domain_name == "pf_jira")
            config = (await session.exec(stmt)).first()

        # Pass the dynamic field ID to the client
        jira_task_types = await jira_client.get_task_type_options(config.jira_pf_task_id_custom_field)
        valid_task_types = set(jira_task_types)

        configured_task_types = {r.target_jira_task_type for r in rules if r.target_jira_task_type}
        for tt in configured_task_types:
            if tt in valid_task_types:
                results.append({"project": f"Type: {tt}", "valid": True, "message": "OK"})
            else:
                results.append(
                    {
                        "project": f"Type: {tt}",
                        "valid": False,
                        "message": f"Invalid option. Allowed: {', '.join(valid_task_types) or 'None found'}",
                    }
                )

        report = {"status": "completed", "details": results, "timestamp": datetime.utcnow().isoformat()}

        await redis_client.setex("pf_jira:validation_report", 300, json.dumps(report))
        return report

    except Exception as e:
        logger.exception("Validation task failed.")
        error_report = {"status": "failed", "error": str(e)}
        await redis_client.setex("pf_jira:validation_report", 300, json.dumps(error_report))
        raise
    finally:
        await jira_client.close()


def _evaluate_hardware_thresholds(config: DomainConfig) -> list[str]:
    """Evaluates host memory and disk usage against configured thresholds.

    Args:
        config: The active domain configuration.

    Returns:
        list[str]: A list of formatted alert messages, empty if healthy.
    """
    alerts = []
    if config.alert_mem_threshold_pct > 0:
        mem = psutil.virtual_memory()
        if mem.percent > config.alert_mem_threshold_pct:
            alerts.append(f"⚠️ *Memory Critical*: {mem.percent}% used.")

    if config.alert_disk_threshold_pct > 0:
        disk = psutil.disk_usage("/")
        if disk.percent > config.alert_disk_threshold_pct:
            alerts.append(f"⚠️ *Disk Critical*: {disk.percent}% used.")

    return alerts


async def _evaluate_queue_depth(redis_client: redis.Redis, threshold: int) -> list[str]:
    """Evaluates ARQ queue backlog to detect worker starvation.

    Args:
        redis_client: The active Redis connection pool.
        threshold: The maximum acceptable queue length.

    Returns:
        list[str]: A list of formatted alert messages, empty if healthy.
    """
    if threshold <= 0:
        return []

    try:
        queue_len = await redis_client.zcard("pf_jira_queue")
        if queue_len > threshold:
            return [f"⚠️ *Queue Backlog*: {queue_len} jobs waiting in ARQ."]
    except Exception as e:
        return [f"⚠️ *Redis Unreachable*: Could not read queue depth. ({e})"]

    return []


async def _evaluate_api_connectivity() -> list[str]:
    """Pings required external SaaS platforms to verify network and auth integrity.

    Returns:
        list[str]: A list of formatted alert messages, empty if healthy.
    """
    alerts = []
    pf_client = PeopleForceClient()
    jira_client = JiraClient()

    try:
        pf_ok, pf_err = await pf_client.ping()
        if not pf_ok:
            alerts.append(f"⚠️ *PeopleForce API Offline*: {pf_err}")

        jira_ok, jira_err = await jira_client.ping()
        if not jira_ok:
            alerts.append(f"⚠️ *Jira API Offline*: {jira_err}")
    finally:
        await pf_client.close()
        await jira_client.close()

    return alerts


async def system_health_check_task(ctx: dict[Any, Any]) -> dict[str, Any]:
    """Periodically evaluates infrastructure and API health, yielding dynamically."""
    redis_client = ctx["redis"]

    # 1. Evaluate Dynamic Constraints
    async with async_session_maker() as session:
        stmt = select(DomainConfig).where(DomainConfig.domain_name == "pf_jira")
        config = (await session.exec(stmt)).first()

    if not config or not config.is_active:
        return {"status": "yield_inactive"}

    last_run_key = "pf_jira:last_health_check_timestamp"
    last_run_raw = await redis_client.get(last_run_key)
    if last_run_raw:
        last_run_time = float(last_run_raw)
        now = datetime.now(UTC).timestamp()
        if (now - last_run_time) < config.health_check_interval_seconds:
            return {"status": "yield_interval_not_met"}

    # Register the execution lock
    await redis_client.set(last_run_key, datetime.now(UTC).timestamp())

    # 2. Execute Configured Checks via Helpers
    alerts: list[str] = []

    alerts.extend(_evaluate_hardware_thresholds(config))
    alerts.extend(await _evaluate_queue_depth(redis_client, config.alert_queue_depth_threshold))
    alerts.extend(await _evaluate_api_connectivity())

    # 3. Dispatch Alerts
    if alerts:
        agg_message = "Automated Health Check detected anomalies:\n" + "\n".join(alerts)
        await notify(agg_message)

    return {"status": "executed", "alerts_dispatched": len(alerts)}


class WorkerSettings:
    functions: ClassVar[list[Any]] = [
        sync_pf_to_jira_task,
        sync_jira_to_pf_task,
        validate_routing_rules_task,
        system_health_check_task,  # Register it here
    ]
    redis_settings: ClassVar[Any] = RedisSettings.from_dsn(settings.REDIS_URL)
    queue_name: ClassVar[str] = "pf_jira_queue"
    health_check_key: ClassVar[str] = "arq:worker:pf_jira"
    # Add the cron job to run every 15 minutes (or adjust as needed)
    # Define the Tick pattern: both core sync and health checks "tick" every 60 seconds.
    # The internal logic of the tasks will yield if their dynamic DB intervals haven't been met.
    cron_jobs: ClassVar[list[Any]] = [
        cron(sync_pf_to_jira_task, minute=set(range(60))),
        cron(system_health_check_task, minute=set(range(60))),
    ]

    @staticmethod
    async def on_startup(ctx: dict[Any, Any]) -> None:
        configure_logging()
        logger.info("PF-Jira Worker started")

        ctx["redis"] = redis.from_url(settings.REDIS_URL)

        async with engine.begin() as conn:
            await conn.run_sync(SQLModel.metadata.create_all)

        # Bootstrap dynamic configuration

        async with async_session_maker() as session:
            stmt = select(DomainConfig).where(DomainConfig.domain_name == "pf_jira")
            existing = (await session.exec(stmt)).first()
            if not existing:
                logger.info("Bootstrapping default DomainConfig for pf_jira.")
                default_config = DomainConfig(
                    is_active=True,
                    polling_interval_seconds=300,  # 5 minutes
                    default_jira_project=settings.PF_DEFAULT_JIRA_PROJECT,
                )
                session.add(default_config)
                await session.commit()

    @staticmethod
    async def on_shutdown(ctx: dict[Any, Any]) -> None:
        logger.info("PF-Jira Worker shutting down")
        if "redis" in ctx:
            await ctx["redis"].aclose()
