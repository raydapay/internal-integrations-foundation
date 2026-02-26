import json
import unittest
from unittest.mock import AsyncMock, MagicMock

from src.domain.pf_jira.models import MappingSourceType, RoutingRule, RuleFieldMapping
from src.domain.pf_jira.resolver import FieldDataResolver, SchemaValidationError


class TestFieldDataResolver(unittest.IsolatedAsyncioTestCase):
    """Test suite for the Jira payload transformation pipeline."""

    def setUp(self) -> None:
        self.mock_jira = AsyncMock()
        self.mock_redis = AsyncMock()
        self.resolver = FieldDataResolver(self.mock_jira, self.mock_redis)

        self.rule = RoutingRule(
            id=1,
            target_jira_project="IT",
            field_mappings=[
                RuleFieldMapping(jira_field_id="issuetype", source_type=MappingSourceType.STATIC, source_value="10001"),
                RuleFieldMapping(
                    jira_field_id="assignee", source_type=MappingSourceType.PF_PAYLOAD, source_value="assignee.email"
                ),
                RuleFieldMapping(
                    jira_field_id="labels", source_type=MappingSourceType.STATIC, source_value="PF,Onboarding"
                ),
            ],
        )

        self.pf_payload = {"task_id": 99, "assignee": {"email": "test@example.com"}}

        self.createmeta_response = {
            "issuetype": {"fieldId": "issuetype", "required": True, "schema": {"type": "issuetype"}},
            "assignee": {"fieldId": "assignee", "required": False, "schema": {"type": "user"}},
            "labels": {"fieldId": "labels", "required": False, "schema": {"type": "array", "items": "string"}},
            "summary": {"fieldId": "summary", "required": True, "schema": {"type": "string"}},
        }

    async def test_build_payload_success(self) -> None:
        """Verifies dot-notation extraction, type casting, and accountId resolution."""
        # Setup mocks
        self.mock_redis.get.return_value = json.dumps(self.createmeta_response)

        # FIX: Use MagicMock for the synchronous response object methods
        mock_user_resp = MagicMock()
        mock_user_resp.json.return_value = [{"accountId": "12345-abcde"}]
        mock_user_resp.raise_for_status.return_value = None

        self.mock_jira.client.get.return_value = mock_user_resp

        # Injecting 'summary' to bypass the Strict Validation in Pass 3 for this test
        self.rule.field_mappings.append(
            RuleFieldMapping(jira_field_id="summary", source_type=MappingSourceType.STATIC, source_value="New Hire")
        )

        payload = await self.resolver.build_payload(self.rule, self.pf_payload)

        self.assertEqual(payload["fields"]["issuetype"]["id"], "10001")
        self.assertEqual(payload["fields"]["assignee"]["id"], "12345-abcde")
        self.assertEqual(payload["fields"]["labels"], ["PF", "Onboarding"])
        self.assertEqual(payload["fields"]["summary"], "New Hire")

        # Verify network I/O
        self.mock_jira.client.get.assert_called_once_with("/rest/api/3/user/search?query=test@example.com")

    async def test_strict_validation_catches_missing_required_field(self) -> None:
        """Verifies that missing required fields raise SchemaValidationError."""
        # Add a custom required field that is NOT in the bypass whitelist
        self.createmeta_response["customfield_strict"] = {"required": True, "name": "Cost Center"}
        self.mock_redis.get.return_value = json.dumps(self.createmeta_response)

        mock_user_resp = MagicMock()
        mock_user_resp.json.return_value = [{"accountId": "12345-abcde"}]
        self.mock_jira.client.get.return_value = mock_user_resp

        # No mapping is provided for 'customfield_strict', should throw SchemaValidationError
        with self.assertRaises(SchemaValidationError):
            await self.resolver.build_payload(self.rule, self.pf_payload)


async def test_allowed_values_mismatch(self) -> None:
    """Verifies the validator catches when a mapping uses an option Jira no longer recognizes."""
    # Inject a restricted select-list into the mocked createmeta
    self.createmeta_response["customfield_10045"] = {
        "fieldId": "customfield_10045",
        "required": False,
        "schema": {"type": "option"},
        "allowedValues": [{"id": "10001", "value": "Engineering"}, {"id": "10002", "value": "Human Resources"}],
    }
    self.mock_redis.get.return_value = json.dumps(self.createmeta_response)

    # FIX: Provide a synchronous MagicMock for the assignee lookup to prevent coroutine subscript errors
    mock_user_resp = MagicMock()
    mock_user_resp.json.return_value = [{"accountId": "12345-abcde"}]
    mock_user_resp.raise_for_status.return_value = None
    self.mock_jira.client.get.return_value = mock_user_resp

    # Map a deprecated/invalid static value to the restricted field
    self.rule.field_mappings.append(
        RuleFieldMapping(
            jira_field_id="customfield_10045",
            source_type=MappingSourceType.STATIC,
            source_value="Marketing",  # Does not exist in allowedValues
        )
    )

    with self.assertRaises(SchemaValidationError) as context:
        await self.resolver.build_payload(self.rule, self.pf_payload)

    # Assert the circuit breaker provides the exact available options to the admin
    error_msg = str(context.exception)
    self.assertIn("customfield_10045", error_msg)
    self.assertIn("Marketing", error_msg)
    self.assertIn("Engineering, Human Resources", error_msg)
