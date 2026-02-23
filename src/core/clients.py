from typing import Any

import httpx
from fastapi import status
from loguru import logger

from src.config.settings import settings


class BaseClient:
    """Base asynchronous client for external API interactions."""

    def __init__(
        self,
        base_url: str,
        headers: dict[str, str] | None = None,
        auth: tuple[str, str] | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.headers = headers or {}
        self.client = httpx.AsyncClient(base_url=self.base_url, headers=self.headers, auth=auth, timeout=15.0)

    async def close(self) -> None:
        await self.client.aclose()


class NotificationClient(BaseClient):
    """Adapter for verifying notification channel integrity."""

    def __init__(self) -> None:
        # Initialized with a dummy base to satisfy BaseClient;
        # actual calls use absolute URLs from settings.
        super().__init__("https://api.telegram.org")

    async def ping_slack(self) -> tuple[str, str]:
        """Checks Slack Webhook connectivity via a empty POST request.

        Returns:
            tuple[str, str]: (status_tag, detail_message)
        """
        if not settings.SLACK_WEBHOOK_URL:
            return "warning", "Token not configured"

        try:
            # We use a POST with an empty body.
            # A valid webhook returns 400 "invalid_payload" or "no_text".
            # An invalid webhook returns 403 or 404.
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(settings.SLACK_WEBHOOK_URL, json={})

                # 200 is theoretically possible if Slack changes behavior,
                # 400 is the expected response for an empty payload on a valid webhook.
                if resp.status_code in [200, 400]:
                    return "success", "Webhook Valid"

                if resp.status_code in [403, 404]:
                    return "danger", "Invalid/Revoked Webhook"

                return "danger", f"HTTP {resp.status_code}"
        except Exception as e:
            return "danger", f"Connection Failed: {e!s}"

    async def ping_telegram(self) -> tuple[str, str]:
        """Checks Telegram Bot Token via getMe endpoint."""
        if not settings.TELEGRAM_BOT_TOKEN:
            return "warning", "Token not configured"

        url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/getMe"
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(url)
                if resp.status_code == status.HTTP_200_OK:
                    data = resp.json()
                    return "success", f"Bot: @{data['result']['username']}"
                return "danger", f"Invalid Token (HTTP {resp.status_code})"
        except Exception as e:
            return "danger", str(e)


class PeopleForceClient(BaseClient):
    """Adapter for the PeopleForce HRIS API v3."""

    def __init__(self) -> None:
        headers = {"X-API-KEY": settings.PF_API_KEY, "Accept": "application/json"}
        super().__init__("https://app.peopleforce.io/api/public/v3", headers=headers)

    async def get_tasks(self, watermark_id: int | None = None) -> list[dict[str, Any]]:
        """Polls tasks from PeopleForce, using a watermark to strictly limit historical fetching."""
        all_tasks: list[dict[str, Any]] = []

        # 1. Fetch all Open tasks (Unbounded)
        current_page = 1
        while True:
            response = await self.client.get(f"/tasks?completed=false&page={current_page}")
            response.raise_for_status()
            payload = response.json()
            all_tasks.extend(payload.get("data", []))

            if current_page >= payload.get("metadata", {}).get("pagination", {}).get("pages", 1):
                break
            current_page += 1

        # 2. Fetch Completed tasks (Bounded by Watermark)
        current_page = 1
        while True:
            response = await self.client.get(f"/tasks?completed=true&page={current_page}")
            response.raise_for_status()
            payload = response.json()
            tasks = payload.get("data", [])

            if not tasks:
                break

            if watermark_id is not None:
                # API sorts by ID DESC. The last item is the smallest ID on this page.
                lowest_id_on_page = int(tasks[-1]["id"])

                # Filter out tasks older than the watermark
                valid_tasks = [t for t in tasks if int(t["id"]) >= watermark_id]
                all_tasks.extend(valid_tasks)

                # Early Exit: If the lowest ID on this page is below the watermark,
                # all subsequent pages contain strictly older tasks.
                if lowest_id_on_page < watermark_id:
                    break
            else:
                all_tasks.extend(tasks)

            if current_page >= payload.get("metadata", {}).get("pagination", {}).get("pages", 1):
                break
            current_page += 1

        return all_tasks

    async def ping(self) -> tuple[bool, str]:
        """Verifies API connectivity and authentication validity.

        Returns:
            tuple[bool, str]: A boolean indicating success, and a detailed status message.
        """
        try:
            response = await self.client.get("/employees?page=1")
            response.raise_for_status()
            return True, "Connected & Authenticated"
        except httpx.HTTPStatusError as e:
            return False, f"HTTP Error: {e.response.status_code}"
        except httpx.RequestError as e:
            return False, f"Network Error: {e!s}"

    async def complete_task(self, task_id: str) -> None:
        """Transitions a specific task to a completed state in PeopleForce.

        Args:
            task_id: The unique identifier of the PeopleForce task.

        Raises:
            httpx.HTTPStatusError: If the PeopleForce API rejects the mutation.
            httpx.RequestError: If the network connection drops.
        """
        response = await self.client.put(f"/tasks/{task_id}/complete")

        if response.status_code >= status.HTTP_400_BAD_REQUEST:
            logger.error(f"Failed to complete PF task {task_id}: {response.text}")

        response.raise_for_status()


class JiraClient(BaseClient):
    """Adapter for the Jira Software API v3."""

    def __init__(self) -> None:
        headers = {"Accept": "application/json"}
        auth_tuple: tuple[str, str] | None = None

        raw_auth = settings.JIRA_AUTH

        if raw_auth and ":" in raw_auth:
            username, token = raw_auth.split(":", 1)
            auth_tuple = (username, token)
        else:
            logger.error(
                "JIRA_AUTH is missing the email prefix. "
                "Jira Cloud requires 'email@domain.com:api_token' for authentication."
            )

        super().__init__(settings.JIRA_BASE_URL, headers=headers, auth=auth_tuple)
        self._transition_cache: dict[str, str] = {}

    async def get_task_type_options(self, field_id) -> list[str]:
        """Dynamically fetches the allowed values for the Task Type custom field."""
        if not field_id:
            logger.warning("No Task Type Custom Field ID provided to JiraClient.")
            return []
        try:
            # 1. Fetch contexts associated with the custom field
            contexts_url = f"/rest/api/3/field/{field_id}/context"
            response = await self.client.get(contexts_url)
            response.raise_for_status()
            contexts = response.json().get("values", [])

            options = []
            # 2. Fetch the allowed options for each context
            for ctx in contexts:
                context_id = ctx["id"]
                options_url = f"/rest/api/3/field/{field_id}/context/{context_id}/option"
                opt_response = await self.client.get(options_url)
                opt_response.raise_for_status()
                for opt in opt_response.json().get("values", []):
                    options.append(opt["value"])

            # Return unique sorted options
            return sorted(list(set(options)))
        except httpx.HTTPStatusError as e:
            logger.error(f"Failed to fetch Task Type options from Jira API: {e}")
            return []

    async def get_account_id_by_email(self, email: str) -> str | None:
        """Resolves a Jira accountId from an email address.

        Requires the 'Browse users and groups' permission.
        """
        if not email:
            return None

        # Jira user search API
        response = await self.client.get(f"/rest/api/3/user/search?query={email}")

        if response.status_code != status.HTTP_200_OK:
            logger.warning(f"Failed to query Jira user for {email}: {response.text}")
            return None

        users = response.json()
        if not users:
            return None

        # Return the first matching account ID (assuming 1:1 email mapping)
        return users[0].get("accountId")

    async def create_issue(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Creates a new issue in Jira."""
        response = await self.client.post("/rest/api/3/issue", json=payload)

        if response.status_code >= status.HTTP_400_BAD_REQUEST:
            logger.error(f"Jira API rejected payload [{response.status_code}]: {response.text}")

        response.raise_for_status()
        return response.json()

    async def ping(self) -> tuple[bool, str]:
        """Verifies API connectivity and authentication validity.

        Returns:
            tuple[bool, str]: A boolean indicating success, and a detailed status message.
        """
        try:
            response = await self.client.get("/rest/api/3/myself")
            response.raise_for_status()
            user_data = response.json()
            return True, f"Authenticated as {user_data.get('emailAddress', 'Unknown')}"
        except httpx.HTTPStatusError as e:
            return False, f"HTTP Error: {e.response.status_code}"
        except httpx.RequestError as e:
            return False, f"Network Error: {e!s}"

    async def update_issue(self, issue_id_or_key: str, payload: dict[str, Any]) -> None:
        """Updates an existing issue in Jira in-place via a PUT request."""
        response = await self.client.put(f"/rest/api/3/issue/{issue_id_or_key}", json=payload)
        if response.status_code >= status.HTTP_400_BAD_REQUEST:
            logger.error(f"Jira API rejected update payload [{response.status_code}]: {response.text}")
        response.raise_for_status()

    async def get_all_projects(self) -> list[dict[str, str]]:
        """Fetches all accessible Jira projects for UI mapping dropdowns.

        Returns:
            list[dict[str, str]]: A list of dictionaries containing project 'key' and 'name'.
        """
        response = await self.client.get("/rest/api/3/project")

        if response.status_code != status.HTTP_200_OK:
            logger.error(f"Failed to fetch Jira projects: {response.text}")
            return []

        return [{"key": p["key"], "name": p["name"]} for p in response.json()]

    async def transition_issue_to_done(self, issue_id_or_key: str) -> None:
        """Dynamically finds and executes a transition to a positive 'Done' status.

        Implements an LRU-style memoization cache keyed by the Jira Project Prefix
        to prevent N+1 API calls during batch reconciliation.
        """
        project_key = issue_id_or_key.split("-", maxsplit=1)[0]

        # 1. Check Cache
        if project_key in self._transition_cache:
            try:
                await self.transition_issue(issue_id_or_key, self._transition_cache[project_key])
                return
            except httpx.HTTPStatusError as e:
                if e.response.status_code == status.HTTP_400_BAD_REQUEST:
                    logger.warning(
                        f"Cached transition {self._transition_cache[project_key]} rejected for {issue_id_or_key}. "
                        "Invalidating."
                    )
                    del self._transition_cache[project_key]
                else:
                    raise

        # 2. Fetch available transitions for this specific issue
        resp = await self.client.get(f"/rest/api/3/issue/{issue_id_or_key}/transitions")
        resp.raise_for_status()

        transitions = resp.json().get("transitions", [])

        # 3. Identify the transition ID using priority heuristics
        target_transition_id = None
        fallback_transition_id = None

        positive_terminal_names = {"done", "completed", "resolved", "closed", "processed"}

        for t in transitions:
            status_category_key = t.get("to", {}).get("statusCategory", {}).get("key")
            name = t.get("name", "").lower()

            if status_category_key == "done":
                # Priority 1: Exact match against known positive completion names
                if name in positive_terminal_names:
                    target_transition_id = t.get("id")
                    break

                # Priority 2: Generic terminal state fallback (e.g., 'Cancelled')
                if not fallback_transition_id:
                    fallback_transition_id = t.get("id")

        target_transition_id = target_transition_id or fallback_transition_id

        if not target_transition_id:
            logger.warning(f"No terminal transition found for {issue_id_or_key}.")
            return

        # 4. Cache and Execute
        self._transition_cache[project_key] = target_transition_id
        await self.transition_issue(issue_id_or_key, target_transition_id)

    async def transition_issue(self, issue_id_or_key: str, transition_id: str) -> None:
        """Changes the status of a Jira issue via a workflow transition."""
        payload = {"transition": {"id": transition_id}}
        response = await self.client.post(f"/rest/api/3/issue/{issue_id_or_key}/transitions", json=payload)

        if response.status_code >= status.HTTP_400_BAD_REQUEST:
            logger.error(f"Failed to transition {issue_id_or_key} to {transition_id}: {response.text}")
        response.raise_for_status()

    async def validate_project_permissions(self, project_key: str) -> tuple[bool, list[str]]:
        """Evaluates the active token's access rights against a specific Jira project.

        Args:
            project_key: The Jira Project Key to evaluate (e.g., 'HR').

        Returns:
            tuple[bool, list[str]]: A boolean indicating if the token is fully authorized,
            and a list of any explicitly missing permissions.

        Raises:
            httpx.HTTPStatusError: If the Jira API rejects the request (e.g., project not found).
        """
        permissions_to_check = [
            "CREATE_ISSUES",
            "EDIT_ISSUES",
            "ASSIGN_ISSUES",
            "MODIFY_REPORTER",
            "TRANSITION_ISSUES",
            "ADD_COMMENTS",
        ]
        perm_string = ",".join(permissions_to_check)

        response = await self.client.get(
            f"/rest/api/3/mypermissions?projectKey={project_key}&permissions={perm_string}"
        )
        response.raise_for_status()

        granted_perms = response.json().get("permissions", {})
        missing_permissions = []

        for perm in permissions_to_check:
            # Jira returns havePermission: true if the token is authorized
            if not granted_perms.get(perm, {}).get("havePermission", False):
                missing_permissions.append(perm)

        return len(missing_permissions) == 0, missing_permissions

    async def add_comment(self, issue_id_or_key: str, comment_text: str) -> None:
        """Injects a comment into a Jira issue using the Atlassian Document Format (ADF)."""
        payload = {
            "body": {
                "type": "doc",
                "version": 1,
                "content": [{"type": "paragraph", "content": [{"text": comment_text, "type": "text"}]}],
            }
        }
        response = await self.client.post(f"/rest/api/3/issue/{issue_id_or_key}/comment", json=payload)

        if response.status_code >= status.HTTP_400_BAD_REQUEST:
            logger.error(f"Failed to add comment to {issue_id_or_key}: {response.text}")
        response.raise_for_status()

    async def search_issues(self, jql: str, fields: list[str] | None = None) -> list[dict[str, Any]]:
        """Executes a JQL search and returns matching issues, handling pagination.

        Args:
            jql: The Jira Query Language string.
            fields: A list of specific fields to return. Defaults to ["id", "key"].

        Returns:
            list[dict[str, Any]]: A list of Jira issue dictionaries.
        """
        fields = fields or ["id", "key"]
        all_issues = []
        start_at = 0
        max_results = 100

        while True:
            payload = {"jql": jql, "startAt": start_at, "maxResults": max_results, "fields": fields}
            response = await self.client.post("/rest/api/3/search", json=payload)

            if response.status_code >= status.HTTP_400_BAD_REQUEST:
                logger.error(f"JQL search failed [{response.status_code}]: {response.text}")
            response.raise_for_status()

            data = response.json()
            issues = data.get("issues", [])
            all_issues.extend(issues)

            if start_at + len(issues) >= data.get("total", 0) or not issues:
                break
            start_at += len(issues)

        return all_issues
