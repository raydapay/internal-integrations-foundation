"""
Jira Payload Resolution and Schema Validation Pipeline.
"""

import json
import logging
import re
from html.parser import HTMLParser
from typing import Any

from redis.asyncio import Redis

from src.core.clients import JiraClient
from src.domain.pf_jira.models import MappingSourceType, RoutingRule, RuleFieldMapping

logger = logging.getLogger(__name__)


class PeopleForceADFParser(HTMLParser):
    """
    Translates PeopleForce rich-text HTML into strict Atlassian Document Format (ADF).

    Attributes:
        root_node (dict): The root ADF document structure.
        block_stack (list): Tracks nested block elements (e.g., lists).
        current_paragraph (dict | None): The active paragraph block for inline nodes.
        current_marks (set): Active formatting marks (strong, em, etc.).
        skip_data (int): Counter to suppress inner text rendering (e.g., inside auth links).
    """

    def __init__(self) -> None:
        # convert_charrefs=True ensures &nbsp; is converted to \xa0 before hitting handle_data
        super().__init__(convert_charrefs=True)
        self.root_node: dict[str, Any] = {"type": "doc", "version": 1, "content": []}
        self.block_stack: list[dict[str, Any]] = [self.root_node]
        self.current_paragraph: dict[str, Any] | None = None
        self.current_marks: set[str] = set()
        self.skip_data: int = 0

    def _ensure_paragraph(self) -> None:
        """Ensures an active paragraph block exists, respecting ADF nesting rules."""
        if self.current_paragraph is None:
            self.current_paragraph = {"type": "paragraph", "content": []}
            parent = self.block_stack[-1]

            if parent["type"] == "bulletList":
                new_li = {"type": "listItem", "content": [self.current_paragraph]}
                parent["content"].append(new_li)
                self.block_stack.append(new_li)
            else:
                parent["content"].append(self.current_paragraph)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = dict(attrs)

        if tag in ("b", "strong"):
            self.current_marks.add("strong")
        elif tag in ("i", "em"):
            self.current_marks.add("em")
        elif tag in ("u",):
            self.current_marks.add("underline")
        elif tag == "br":
            self._ensure_paragraph()
            self.current_paragraph["content"].append({"type": "hardBreak"})
        elif tag in ("p", "div"):
            self.current_paragraph = None
        elif tag == "ul":
            self.current_paragraph = None
            new_list = {"type": "bulletList", "content": []}
            self.block_stack[-1]["content"].append(new_list)
            self.block_stack.append(new_list)
        elif tag == "li":
            self.current_paragraph = None
            new_li = {"type": "listItem", "content": []}
            parent = self.block_stack[-1]
            if parent["type"] == "bulletList":
                parent["content"].append(new_li)
                self.block_stack.append(new_li)
        elif tag == "a":
            name = attrs_dict.get("name")
            if name:
                self._add_text(f" [Attachment: {name}]")
                self.skip_data += 1
        elif tag == "img":
            name = attrs_dict.get("name", "attached_image.png")
            self._add_text(f" [Image: {name}]")

    def handle_endtag(self, tag: str) -> None:
        if tag in ("b", "strong"):
            self.current_marks.discard("strong")
        elif tag in ("i", "em"):
            self.current_marks.discard("em")
        elif tag in ("u",):
            self.current_marks.discard("underline")
        elif tag in ("p", "div", "ul", "li"):
            self.current_paragraph = None
            # Only pop if we are closing the matching block type
            if tag == "ul" and self.block_stack[-1]["type"] == "bulletList":
                self.block_stack.pop()
            elif tag == "li" and self.block_stack[-1]["type"] == "listItem":
                self.block_stack.pop()
        elif tag == "a":
            if self.skip_data > 0:
                self.skip_data -= 1

    def handle_data(self, data: str) -> None:
        """Processes text nodes and sanitizes resolved HTML entities."""
        if self.skip_data > 0:
            return

        is_pure_whitespace = not data.strip()
        has_nbsp = "\xa0" in data

        if is_pure_whitespace and not has_nbsp and self.current_paragraph is None:
            return

        self._add_text(data)

    def _add_text(self, text: str) -> None:
        if not text:
            return
        self._ensure_paragraph()

        node: dict[str, Any] = {"type": "text", "text": text}
        if self.current_marks:
            node["marks"] = [{"type": m} for m in self.current_marks]

        self.current_paragraph["content"].append(node)

    def to_adf(self) -> dict[str, Any]:
        """Prunes structurally empty nodes and returns the final ADF dictionary."""
        cleaned_content = self._clean_nodes(self.root_node["content"])
        if not cleaned_content:
            cleaned_content = [{"type": "paragraph", "content": [{"type": "text", "text": " "}]}]

        self.root_node["content"] = cleaned_content
        return self.root_node

    def _clean_nodes(self, nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
        cleaned = []
        for node in nodes:
            if node["type"] == "paragraph" and not node.get("content"):
                continue
            elif node["type"] in ("bulletList", "listItem"):
                node["content"] = self._clean_nodes(node.get("content", []))
                if not node["content"]:
                    continue
            cleaned.append(node)
        return cleaned


def format_html_to_adf(html_payload: str) -> dict[str, Any]:
    """
    Helper function to process an HTML string into ADF.

    Args:
        html_payload (str): The raw HTML string.

    Returns:
        dict[str, Any]: A compliant Atlassian Document Format dictionary.
    """
    if not html_payload:
        return {
            "type": "doc",
            "version": 1,
            "content": [{"type": "paragraph", "content": [{"type": "text", "text": " "}]}],
        }

    parser = PeopleForceADFParser()
    parser.feed(html_payload)
    return parser.to_adf()


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

        if mapping.source_type == MappingSourceType.TEMPLATE:
            return self._resolve_template(mapping.source_value, pf_payload)

        return None

    def _resolve_template(self, template: str, payload: dict[str, Any]) -> str:
        """Interpolates JSONPath variables within a string template.

        Args:
            template: The string containing {{ path.to.var }} placeholders.
            payload: The source dictionary.

        Returns:
            str: The interpolated string. Unresolved paths evaluate to an empty string.
        """
        pattern = re.compile(r"\{\{\s*([\w\.]+)\s*\}\}")

        def replacer(match: re.Match) -> str:
            path = match.group(1)
            val = self._resolve_dot_notation(path, payload)
            return str(val) if val is not None else ""

        return pattern.sub(replacer, template)

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

    def _validate_allowed_values(self, value: Any, field_schema: dict[str, Any], field_id: str) -> None:
        """Validates if the provided value matches Jira's allowed values for the field."""
        if "allowedValues" not in field_schema:
            return

        allowed = field_schema["allowedValues"]
        allowed_ids = {str(opt.get("id")) for opt in allowed if opt.get("id")}
        allowed_values = {str(opt.get("value")) for opt in allowed if opt.get("value")}
        str_val = str(value)

        if str_val not in allowed_ids and str_val not in allowed_values:
            valid_options = ", ".join(allowed_values)
            raise SchemaValidationError(
                f"Value '{str_val}' is invalid for restricted field '{field_id}'. Valid options are: {valid_options}"
            )

    def _format_doc(self, value: Any) -> dict[str, Any]:
        """Formats HTML or mixed text into strict Atlassian Document Format (ADF)."""

        safe_text = str(value) if value is not None else ""

        # 1. Markdown Backward Compatibility: Convert *Text* to <b>Text</b>
        # This ensures Jinja injections like *PeopleForce Metadata* are styled correctly.
        safe_text = re.sub(r"(?<!\\)\*(.+?)(?<!\\)\*", r"<b>\1</b>", safe_text)

        # 2. Normalize raw newlines to <br> so the HTML parser translates them to 'hardBreak'
        safe_text = safe_text.replace("\n", "<br>")

        return format_html_to_adf(safe_text)

    def _format_date(self, value: Any) -> str | None:
        """Formats dates, strictly casting missing values to explicit JSON nulls."""
        if value is None or str(value).strip().lower() in ("", "none", "null"):
            return None
        return str(value).strip()

    async def _format_user(self, value: Any) -> dict[str, str] | None:
        """Resolves an email or ID string into a Jira Account ID object."""
        # Normalize and check for empty/null values before calling the API
        safe_val = str(value).strip() if value is not None else ""
        if not safe_val or safe_val.lower() in ("none", "null"):
            return None

        account_id = await self._resolve_account_id(safe_val)
        # Jira Cloud v3 strictly requires 'accountId' instead of 'id'
        return {"accountId": account_id} if account_id else None

    def _format_array(self, value: Any) -> list[str] | Any:
        """Parses comma-separated strings or lists into an array of strings."""
        if isinstance(value, str):
            return [v.strip() for v in value.split(",")]
        if isinstance(value, list):
            return [str(v) for v in value]
        return value

    async def _transform_value(self, value: Any, field_schema: dict[str, Any], field_id: str) -> Any:
        """Casts the raw value to the exact structural format required by Jira's REST API."""

        # 1. Proactive Domain Constraint Validation
        self._validate_allowed_values(value, field_schema, field_id)

        schema_type = field_schema.get("schema", {}).get("type")

        # 2. Type Dispatcher
        if schema_type == "doc" or field_id == "description":
            return self._format_doc(value)

        if schema_type in ("date", "datetime"):
            return self._format_date(value)

        if schema_type == "user":
            return await self._format_user(value)

        if schema_type == "array" and field_schema.get("schema", {}).get("items") == "string":
            return self._format_array(value)

        if schema_type == "option":
            return {"value": str(value)}

        # 3. Default Fallback
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
