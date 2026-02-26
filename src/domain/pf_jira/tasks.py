import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, ClassVar

import httpx
import psutil
import redis.asyncio as redis
from arq import Retry, cron
from arq.connections import RedisSettings
from fastapi import status
from loguru import logger
from redis.exceptions import LockError
from sqlalchemy import Integer, cast, func
from sqlalchemy.orm import selectinload
from sqlmodel import SQLModel, select
from sqlmodel.ext.asyncio.session import AsyncSession

from src.config.settings import settings
from src.core.clients import JiraClient, PeopleForceClient
from src.core.database import async_session_maker, engine
from src.core.logger import configure_logging
from src.core.notifications import notify
from src.domain.pf_jira.mapping import evaluate_routing_rules
from src.domain.pf_jira.models import (
    DomainConfig,
    MappingSourceType,
    RoutingAction,
    RoutingRule,
    SyncAuditLog,
    SyncOperation,
    SyncState,
)
from src.domain.pf_jira.resolver import FieldDataResolver, SchemaValidationError


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
    resolver: FieldDataResolver


@dataclass
class TaskContext:
    """Encapsulates the parsed state and pre-computed values of a single PeopleForce task."""

    raw: dict[str, Any]
    id: str
    is_completed: bool
    hash: str


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


async def _handle_issue_creation(sync_ctx: SyncContext, task_ctx: TaskContext, jira_payload: dict[str, Any]) -> None:
    """Executes the complete lifecycle for generating a new Jira issue and recording state."""
    task_logger = logger.bind(pf_task_id=task_ctx.id, job_id=sync_ctx.job_id)

    # 1. Assignee Fallback Logic (Keep this as a failsafe if dynamic mapping is empty)
    if "assignee" not in jira_payload["fields"] and sync_ctx.config.jira_fallback_account_id:
        jira_payload["fields"]["assignee"] = {"id": sync_ctx.config.jira_fallback_account_id}

    # 2. Immutable Data Lineage & Folksonomy (Dynamic Config)
    jira_payload["properties"] = [
        {"key": sync_ctx.config.jira_entity_property_key, "value": {"pf_task_id": task_ctx.id}}
    ]

    if "labels" not in jira_payload["fields"]:
        jira_payload["fields"]["labels"] = []

    if sync_ctx.config.jira_tracking_label not in jira_payload["fields"]["labels"]:
        jira_payload["fields"]["labels"].append(sync_ctx.config.jira_tracking_label)

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
                    "project": jira_payload["fields"].get("project", {}).get("key"),
                    "dynamic_fields_mapped": list(jira_payload["fields"].keys()),
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
    sync_ctx: SyncContext, task_ctx: TaskContext, jira_payload: dict[str, Any], state_record: SyncState
) -> None:
    """Executes the mutation lifecycle for an existing Jira issue, handling state reconciliation."""
    task_logger = logger.bind(pf_task_id=task_ctx.id, job_id=sync_ctx.job_id)
    issue_key = state_record.jira_issue_key

    # CRITICAL: Jira's PUT endpoint rejects attempts to modify 'project' or 'issuetype'.
    # We must strip them from the resolver's output before dispatching the update.
    update_fields = dict(jira_payload["fields"])
    update_fields.pop("project", None)
    update_fields.pop("issuetype", None)

    if "assignee" not in update_fields:
        if sync_ctx.config.jira_fallback_account_id:
            update_fields["assignee"] = {"id": sync_ctx.config.jira_fallback_account_id}
        else:
            update_fields["assignee"] = None  # Explicitly unassign if mapping fails or is empty

    update_payload = {"fields": update_fields}
    task_logger.debug(f"Computed Update Payload: {json.dumps(update_payload)}")

    update_payload = {"fields": update_fields}
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
                    "dynamic_fields_updated": list(update_fields.keys()),
                    "completed_status_triggered": task_ctx.is_completed,
                },
                ensure_ascii=False,
            ),
        )
    )
    sync_ctx.stats["updated"] += 1
    task_logger.info(f"Updated Jira issue {issue_key}")


async def _handle_jira_400_bad_request(
    e: httpx.HTTPStatusError,
    ctx: SyncContext,
    task_id: str,
    jira_payload: dict[str, Any],
    task_logger: Any,
) -> bool:
    """Evaluates an HTTP 400 rejection from Jira to determine the failure vector.

    Args:
        e: The HTTP error exception.
        ctx: The active synchronization context.
        task_id: The PeopleForce task ID.
        jira_payload: The computed Jira payload that was rejected.
        task_logger: The bound logger for the current task.

    Returns:
        bool: True if the payload was dropped to the DLQ (caller should yield).

    Raises:
        Retry: If structural schema drift is suspected, forcing a cache purge and retry.
    """
    try:
        error_payload = e.response.json()
        jira_errors = error_payload.get("errors", {})
    except Exception:
        jira_errors = {}

    # Identify state/permission failures from dynamic identity mappings
    state_failure_keys = {"assignee", "reporter"}

    if any(k in jira_errors for k in state_failure_keys):
        task_logger.error(f"Dynamic state mapping rejected by Jira (DLQ): {jira_errors}")

        ctx.session.add(
            SyncAuditLog(
                pf_task_id=task_id,
                operation=SyncOperation.ERROR,
                details=json.dumps(
                    {
                        "error_type": "Identity Mapping Failure",
                        "jira_rejection": jira_errors,
                        "action": "payload_dropped_to_dlq",
                    },
                    ensure_ascii=False,
                ),
            )
        )
        await ctx.session.commit()
        ctx.stats["skipped"] += 1
        return True

    # Otherwise, assume structural schema drift (The 400 Trap)
    project = jira_payload["fields"]["project"]["key"]
    issuetype = jira_payload["fields"]["issuetype"]["id"]
    cache_key = f"jira:createmeta:{project}:{issuetype}"

    task_logger.warning(f"Jira HTTP 400. Suspected schema drift. Purging cache: {cache_key}. Errors: {jira_errors}")
    await ctx.redis_client.delete(cache_key)

    # Defers the task for 5 seconds. The retry will fetch the fresh schema,
    # fail Pass 3 validation, and cleanly trip the SchemaValidationError block.
    raise Retry(defer=5) from e


async def _process_single_task(task: dict[str, Any], ctx: SyncContext) -> None:
    """Evaluates and synchronizes a single PeopleForce task against the Jira state matrix.

    Integrates the FieldDataResolver pipeline to validate target payloads against
    dynamic Jira schemas, acting as a circuit breaker against upstream configuration drift.

    Args:
        task: The raw dictionary payload from the PeopleForce API.
        ctx: The global synchronization context object.

    Raises:
        LockError: If the Redis lock cannot be acquired (handled gracefully by the caller).
    """
    task_id = str(task.get("id"))
    task_logger = logger.bind(pf_task_id=task_id, job_id=ctx.job_id)

    if ctx.cutoff_date and _is_task_historical(task, ctx.cutoff_date, task_id):
        ctx.stats["skipped"] += 1
        return

    # Extract Base Task Context

    task_ctx = TaskContext(raw=task, id=task_id, is_completed=task.get("completed", False), hash=_compute_hash(task))

    lock_key = f"lock:pf_jira:task:{task_id}"

    try:
        async with ctx.redis_client.lock(lock_key, timeout=10.0, blocking_timeout=2.0):
            statement = select(SyncState).where(SyncState.pf_entity_type == "task", SyncState.pf_entity_id == task_id)
            state_record = (await ctx.session.exec(statement)).first()

            # Optimization: Evaluate hash delta BEFORE triggering the resolver pipeline.
            # Prevents unnecessary Jira createmeta API calls for unchanged tasks.
            if state_record and state_record.last_sync_hash == task_ctx.hash:
                ctx.stats["skipped"] += 1
                task_logger.debug(
                    f"Skipped (No Delta): Payload hash {task_ctx.hash} exactly matches "
                    "the state stored in the database."
                )
                return

            try:
                # Execute the unified Phase 2 routing and payload assembly pipeline
                action, jira_payload = await evaluate_routing_rules(
                    session=ctx.session, pf_payload=task, resolver=ctx.resolver
                )

                if action in [RoutingAction.DROP, getattr(RoutingAction, "IGNORE", None)]:
                    task_logger.debug(f"Task {task_id} dropped by firewall routing rule.")
                    ctx.stats["skipped"] += 1
                    return

                try:
                    if not state_record:
                        await _handle_issue_creation(ctx, task_ctx, jira_payload)
                    else:
                        await _handle_issue_update(ctx, task_ctx, jira_payload, state_record)

                except httpx.HTTPStatusError as e:
                    # Reactive Cache Invalidation & DLQ Routing (The 400 Trap)
                    if e.response.status_code == status.HTTP_400_BAD_REQUEST:
                        is_dlq = await _handle_jira_400_bad_request(e, ctx, task_id, jira_payload, task_logger)
                        if is_dlq:
                            return
                    raise

                await ctx.session.commit()

            except SchemaValidationError as e:
                # Phase 2 Circuit Breaker: Intercepts schema drift to prevent Poison Pill loops
                task_logger.error(f"Schema drift detected for task {task_id}: {e}")
                await notify(f"⚠️ *Schema Drift Detected*\nJira metadata changed. Task `{task_id}` blocked:\n`{e}`")
                # Yielding prevents the ARQ worker from raising an exception and retrying infinitely
                ctx.stats["skipped"] += 1

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

    # 2. Initialize the Transformation & Validation Pipeline
    resolver = FieldDataResolver(jira_client=jira_client, redis=redis_client)

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
        resolver=resolver,  # 3. Inject into the execution context
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


async def zombie_recovery_task(ctx: dict[Any, Any]) -> dict[str, Any]:
    """Sweeps Jira for recently closed tasks to catch missed webhooks.

    Executes a reverse-vector JQL query to identify issues closed in the
    last 24 hours and reconciles them against the local SyncState.
    """
    job_id = ctx.get("job_id", "unknown")
    task_logger = logger.bind(job_id=job_id, operation="zombie_sweeper")
    jira_client = JiraClient()

    stats = {"found": 0, "recovered": 0, "errors": 0}

    try:
        # Resolve tracking label dynamically for the sweep
        async with async_session_maker() as session:
            stmt = select(DomainConfig).where(DomainConfig.domain_name == "pf_jira")
            config = (await session.exec(stmt)).first()
            tracking_label = config.jira_tracking_label if config else "PeopleForce"

        # Target issues completed in the last 24 hours with the integration label
        jql = f"labels = {tracking_label} AND statusCategory = Done AND updated >= -24h"
        issues = await jira_client.search_issues(jql, fields=["status"])
        stats["found"] = len(issues)

        if not issues:
            task_logger.debug("No recently closed Jira issues found. Sweeper yielding.")
            return stats

        for issue in issues:
            issue_key = issue["key"]
            try:
                # Pre-flight DB evaluation to avoid acquiring the Redis lock unnecessarily.
                # Actual idempotency is guaranteed by the delegate function.
                async with async_session_maker() as session:
                    stmt = select(SyncState).where(
                        SyncState.jira_issue_key == issue_key, SyncState.is_completed.is_(False)
                    )
                    unresolved_state = (await session.exec(stmt)).first()

                if unresolved_state:
                    task_logger.info(f"Zombie detected: {issue_key}. Executing recovery delegate.")
                    # Delegate to the existing webhook processor
                    await sync_jira_to_pf_task(ctx, issue_key)
                    stats["recovered"] += 1

            except Exception as e:
                task_logger.error(f"Failed to recover zombie {issue_key}: {e}")
                stats["errors"] += 1

    except Exception as err:
        task_logger.exception("Catastrophic failure in zombie sweeper.")
        raise Retry(defer=ctx.get("job_try", 1) * 300) from err
    finally:
        await jira_client.close()

    return stats


async def validate_routing_rules_task(ctx: dict[Any, Any]) -> dict[str, Any]:
    """Proactively validates active RoutingRules against live Jira schemas.

    Implements the Phase 2 Nightly Circuit Breaker pattern. Detects schema drift
    (e.g., missing fields, newly required fields) and safely disables violating
    rules before they poison the active worker queues.
    """
    job_id = ctx.get("job_id", "unknown")
    task_logger = logger.bind(job_id=job_id, operation="schema_validator")

    jira_client = JiraClient()
    redis_client = ctx["redis"]
    resolver = FieldDataResolver(jira_client=jira_client, redis=redis_client)

    # CRITICAL FIX: Ensure status and details array exist for the UI payload
    stats = {"validated": 0, "disabled": 0, "skipped": 0, "status": "completed", "details": []}

    try:
        async with async_session_maker() as session:
            # Eagerly load mappings to prevent DetachedInstanceError
            stmt = (
                select(RoutingRule)
                .where(RoutingRule.is_active.is_(True))
                .options(selectinload(RoutingRule.field_mappings))
            )
            rules = (await session.exec(stmt)).all()

            for rule in rules:
                # 1. Isolate the target Issue Type
                issuetype_mapping = next((m for m in rule.field_mappings if m.jira_field_id == "issuetype"), None)

                if not issuetype_mapping or issuetype_mapping.source_type != MappingSourceType.STATIC:
                    task_logger.debug(f"Rule {rule.id} lacks a static issuetype. Skipping proactive validation.")
                    stats["skipped"] += 1
                    continue

                issue_type_id = issuetype_mapping.source_value

                try:
                    # 2. Fetch live schema.
                    schema = await resolver._get_createmeta(rule.target_jira_project, issue_type_id)

                    # 3. Dry-Run Structural Validation
                    mapped_fields = {m.jira_field_id for m in rule.field_mappings if m.jira_field_id != "issuetype"}

                    for field_id in mapped_fields:
                        if field_id not in schema:
                            raise SchemaValidationError(
                                f"Mapped field '{field_id}' no longer exists on the Create Screen."
                            )

                    # Explicitly whitelist natively injected fields so they don't trigger validation failures
                    for field_id, field_meta in schema.items():
                        if (
                            field_meta.get("required")
                            and field_id not in mapped_fields
                            and field_id
                            not in ["project", "issuetype", "summary", "description", "duedate", "reporter"]
                        ):
                            raise SchemaValidationError(
                                f"Jira requires field '{field_id}', but it is missing from the rule mappings."
                            )

                    stats["validated"] += 1
                    stats["details"].append(
                        {
                            "project": rule.target_jira_project,
                            "valid": True,
                            "message": f"Rule {rule.id} mapping is valid.",
                        }
                    )

                except SchemaValidationError as e:
                    # 4. Deterministic Schema Drift -> Trip the Circuit Breaker
                    task_logger.error(f"Rule {rule.id} failed validation: {e}. Disabling rule.")

                    rule.is_active = False
                    session.add(rule)
                    await session.commit()
                    await notify(
                        f"🛑 *Circuit Breaker Tripped*\n"
                        f"Routing Rule `{rule.id}` disabled due to schema drift.\n"
                        f"*Project:* {rule.target_jira_project}\n*Reason:* {e}"
                    )
                    stats["disabled"] += 1
                    stats["details"].append({"project": rule.target_jira_project, "valid": False, "message": str(e)})

        # CRITICAL FIX: Write the final report to Redis so the UI can break out of the polling loop
        await redis_client.setex("pf_jira:validation_report", 300, json.dumps(stats))

    except (httpx.TimeoutException, httpx.HTTPStatusError) as net_err:
        task_logger.warning(f"Network error during schema fetch: {net_err}. Executing geometric backoff.")
        retry_count = ctx.get("job_try", 1)
        raise Retry(defer=2**retry_count) from net_err

    except Exception as err:
        task_logger.exception("Catastrophic failure in proactive validation pipeline.")
        error_report = {"status": "failed", "error": str(err)}
        await redis_client.setex("pf_jira:validation_report", 300, json.dumps(error_report))
        raise

    finally:
        await jira_client.close()

    return stats


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
        system_health_check_task,
        zombie_recovery_task,
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
        cron(zombie_recovery_task, hour={3}, minute={0}),
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
