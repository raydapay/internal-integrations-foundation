"""
Jira Payload Resolution and Schema Validation Pipeline.
"""

import json
import logging
from typing import Any

from redis.asyncio import Redis

from src.core.clients import JiraClient
from src.domain.pf_jira.models import MappingSourceType, RoutingRule, RuleFieldMapping

logger = logging.getLogger(__name__)


class SchemaValidationError(Exception):
    """Raised when the resolved payload violates the Jira createmeta schema."""

    pass


class FieldDataResolver:
    """Pipeline for transforming RoutingRules into validated Jira API payloads."""

    def __init__(self, jira_client: JiraClient, redis: Redis) -> None:
        """Initializes the FieldDataResolver.

        Args:
            jira_client: Authenticated Jira API client.
            redis: Async Redis client for caching createmeta schemas.
        """
        self.jira = jira_client
        self.redis = redis
        self.cache_ttl = 3600  # 1 hour schema cache

    async def build_payload(self, rule: RoutingRule, pf_payload: dict[str, Any]) -> dict[str, Any]:
        """Constructs a validated Jira issue payload.

        Args:
            rule: The triggered RoutingRule containing field mappings.
            pf_payload: The raw JSON webhook payload from PeopleForce.

        Returns:
            dict[str, Any]: A structural Jira payload ready for POST /issue.

        Raises:
            SchemaValidationError: If required fields are missing or types are invalid.
            ValueError: If the issuetype mapping is missing from the rule.
        """
        # Pass 1: Extract Base Primitives
        issue_type_id = self._extract_primitive(rule.field_mappings, "issuetype", pf_payload)
        if not issue_type_id:
            raise ValueError(f"Rule {rule.id} lacks an 'issuetype' mapping.")

        schema = await self._get_createmeta(rule.target_jira_project, issue_type_id)

        payload_fields: dict[str, Any] = {
            "project": {"key": rule.target_jira_project},
            "issuetype": {"id": issue_type_id},
        }

        # Pass 2: Map and Transform
        for mapping in rule.field_mappings:
            if mapping.jira_field_id == "issuetype":
                continue

            raw_value = self._extract_value(mapping, pf_payload)
            if raw_value is None:
                continue

            field_schema = schema.get(mapping.jira_field_id)
            if not field_schema:
                raise SchemaValidationError(
                    f"Field '{mapping.jira_field_id}' does not exist on the Create Screen "
                    f"for project {rule.target_jira_project}."
                )

            transformed_value = await self._transform_value(raw_value, field_schema, mapping.jira_field_id)
            payload_fields[mapping.jira_field_id] = transformed_value

        # Pass 3: Strict Required Field Validation
        for field_id, field_meta in schema.items():
            if field_meta.get("required") and field_id not in payload_fields:
                # Bypass implicit fields injected natively by the tasks.py processor
                if field_id not in ["project", "issuetype", "summary", "description", "duedate", "reporter"]:
                    raise SchemaValidationError(f"Missing required Jira field: {field_id}")

        return {"fields": payload_fields}

    def _extract_primitive(
        self, mappings: list[RuleFieldMapping], field_id: str, pf_payload: dict[str, Any]
    ) -> str | None:
        """Finds and extracts a specific field mapping without schema validation.

        Args:
            mappings: List of configured rule mappings.
            field_id: The Jira field ID to locate.
            pf_payload: The source payload from PeopleForce.

        Returns:
            str | None: The extracted value or None if not found.
        """
        for mapping in mappings:
            if mapping.jira_field_id == field_id:
                return (
                    str(self._extract_value(mapping, pf_payload)) if self._extract_value(mapping, pf_payload) else None
                )
        return None

    def _extract_value(self, mapping: RuleFieldMapping, pf_payload: dict[str, Any]) -> Any:
        """Extracts data based on the configured source_type.

        Args:
            mapping: The specific field mapping configuration.
            pf_payload: The source payload from PeopleForce.

        Returns:
            Any: The extracted raw value, or None if extraction fails.
        """
        if mapping.source_type == MappingSourceType.STATIC:
            return mapping.source_value

        if mapping.source_type == MappingSourceType.PF_PAYLOAD:
            return self._resolve_dot_notation(mapping.source_value, pf_payload)

        return None

    def _resolve_dot_notation(self, path: str, payload: dict[str, Any]) -> Any:
        """Traverses a nested dictionary using dot notation (e.g., 'assignee.email').

        Args:
            path: The dot-separated path string.
            payload: The dictionary to traverse.

        Returns:
            Any: The target value, or None if the path is invalid.
        """
        # Strip JSONPath syntax prefix if accidentally provided by administrator
        clean_path = path.lstrip("$.")
        if not clean_path:
            return None

        keys = clean_path.split(".")
        current_node: Any = payload

        for key in keys:
            if not isinstance(current_node, dict):
                return None
            current_node = current_node.get(key)

        return current_node

    async def _get_createmeta(self, project_key: str, issuetype_id: str) -> dict[str, Any]:
        """Fetches the Jira createmeta, utilizing Redis caching to prevent N+1 API calls."""
        cache_key = f"jira:createmeta:{project_key}:{issuetype_id}"
        cached_schema = await self.redis.get(cache_key)

        if cached_schema:
            return json.loads(cached_schema)

        url = f"/rest/api/3/issue/createmeta/{project_key}/issuetypes/{issuetype_id}"

        try:
            resp = await self.jira.client.get(url, params={"maxResults": 100})
            resp.raise_for_status()
        except Exception as e:
            # Safely extract Jira's exact error message (if available) without causing NameErrors
            error_details = getattr(e, "response", None)
            jira_error_text = error_details.text if error_details else str(e)

            logger.error(f"Jira API rejected createmeta request. URL: {url}, Response: {jira_error_text}")
            raise SchemaValidationError(
                f"Jira API Error: {e}. Check that Project '{project_key}' and Issue Type '{issuetype_id}' exist, "
                "and verify the API token has 'Create Issues' permission."
            ) from e

        # Safely parse JSON only if the request succeeded
        try:
            data = resp.json()
        except Exception as json_err:
            raise SchemaValidationError(f"Invalid JSON returned from Jira: {json_err}") from json_err

        fields_schema = data.get("fields", [])

        if not fields_schema:
            logger.error(f"Jira returned empty fields for {project_key}/{issuetype_id}. Raw payload: {data}")
            raise SchemaValidationError(
                f"Empty schema for Project '{project_key}' and IssueType '{issuetype_id}'. "
                "CRITICAL: Verify the API Token has 'Create Issues' permission in this project."
            )

        # Flatten into a usable dictionary for O(1) lookups
        parsed_schema = {field["fieldId"]: field for field in fields_schema}

        # Cache the valid schema in Redis for 1 hour
        await self.redis.setex(cache_key, self.cache_ttl, json.dumps(parsed_schema))

        return parsed_schema

    async def _transform_value(self, value: Any, field_schema: dict[str, Any], field_id: str) -> Any:
        """Casts the raw value to the exact structural format required by Jira's REST API.

        Args:
            value: The raw extracted value.
            field_schema: The specific Jira field schema definition.
            field_id: The Jira field ID being transformed.

        Returns:
            Any: The transformed payload object compliant with Jira API.
        """
        schema_type = field_schema.get("schema", {}).get("type")

        # Proactive Domain Constraint Validation (allowedValues mismatch)
        if "allowedValues" in field_schema:
            allowed = field_schema["allowedValues"]
            # Support resolution by either native Atlassian ID or string value
            allowed_ids = {str(opt.get("id")) for opt in allowed if opt.get("id")}
            allowed_values = {str(opt.get("value")) for opt in allowed if opt.get("value")}
            str_val = str(value)

            if str_val not in allowed_ids and str_val not in allowed_values:
                valid_options = ", ".join(allowed_values)
                raise SchemaValidationError(
                    f"Value '{str_val}' is invalid for restricted field '{field_id}'. "
                    f"Valid options are: {valid_options}"
                )

        if schema_type == "user":
            account_id = await self._resolve_account_id(str(value))
            return {"id": account_id}

        if schema_type == "array" and field_schema.get("schema", {}).get("items") == "string":
            if isinstance(value, str):
                return [v.strip() for v in value.split(",")]
            if isinstance(value, list):
                return [str(v) for v in value]

        if schema_type == "option":
            return {"value": str(value)}

        return value

    async def _resolve_account_id(self, email: str) -> str:
        """Resolves an email address to a Jira accountId via the REST API.

        Args:
            email: The email address to look up.

        Returns:
            str: The corresponding Atlassian accountId.

        Raises:
            ValueError: If no Jira user matches the provided email.
        """
        resp = await self.jira.client.get(f"/rest/api/3/user/search?query={email}")
        resp.raise_for_status()
        users = resp.json()

        if not users:
            raise ValueError(f"No Jira user found for email: {email}")

        return users[0]["accountId"]
