import json

from fastapi import APIRouter, Depends, HTTPException, Request
from loguru import logger

from src.core.security import verify_jira_webhook_signature

router = APIRouter(prefix="/api/v1/webhooks", tags=["Webhooks"])


@router.post("/jira")
async def jira_webhook_ingress(
    request: Request, raw_body: bytes = Depends(verify_jira_webhook_signature)
) -> dict[str, str]:
    """Receives, parses, and dispatches validated Jira webhook events."""

    try:
        payload = json.loads(raw_body)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse Jira payload: {e}")
        raise HTTPException(status_code=400, detail="Invalid JSON payload.") from e

    webhook_event = payload.get("webhookEvent")
    logger.debug(f"Extracted Webhook Event: {webhook_event}")

    if webhook_event == "jira:issue_updated":
        issue = payload.get("issue", {})
        issue_key = issue.get("key")
        status_category = issue.get("fields", {}).get("status", {}).get("statusCategory", {}).get("key")

        logger.debug(f"Evaluating Jira Issue: {issue_key} | Status Category: {status_category}")

        if status_category == "done" and issue_key:
            arq_pool = getattr(request.app.state, "arq_pool", None)

            if not arq_pool:
                logger.error("ARQ pool is not bound to application state. Cannot enqueue.")
                raise HTTPException(status_code=500, detail="Queue unavailable.")

            # Strict isolation boundary enforcement via _queue_name
            job = await arq_pool.enqueue_job("sync_jira_to_pf_task", issue_key, _queue_name="pf_jira_queue")

            if job:
                logger.info(f"Enqueued Return Vector for {issue_key} (Job ID: {job.job_id})")
            else:
                logger.error(f"Redis rejected job enqueue for {issue_key}.")

    return {"status": "accepted"}
