from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/pf-jira", tags=["PeopleForce-Jira Sync"])


class SyncRequest(BaseModel):
    """Payload for triggering the PeopleForce to Jira synchronization."""

    email: str | None = Field(
        default=None,
        description="Optional specific user email to sync. If omitted, performs a full delta-sync.",
    )
    manual_trigger: bool = Field(
        default=False,
        description="Bypass interval checks and force immediate synchronization.",
    )


@router.post("/sync", status_code=status.HTTP_202_ACCEPTED)
async def trigger_sync(request: Request, payload: SyncRequest) -> dict[str, str]:
    """Enqueues a background job to synchronize PeopleForce and Jira.

    This endpoint acts purely as a dispatcher, pushing the payload to the
    isolated ARQ queue and returning immediately to prevent blocking the Event Loop.

    Args:
        request: The incoming HTTP request containing the ARQ pool in application state.
        payload: The synchronization parameters.

    Returns:
        dict[str, str]: A confirmation message and the resulting ARQ job ID.

    Raises:
        HTTPException: If the ARQ pool is unavailable or enqueueing fails.
    """
    arq_pool = getattr(request.app.state, "arq_pool", None)
    if not arq_pool:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="ARQ Redis pool not initialized.",
        )

    # _queue_name enforces the architectural isolation boundary
    job = await arq_pool.enqueue_job("sync_pf_to_jira_task", payload.model_dump(), _queue_name="pf_jira_queue")

    if not job:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to enqueue sync job in Redis.",
        )

    return {"status": "accepted", "job_id": job.job_id}
