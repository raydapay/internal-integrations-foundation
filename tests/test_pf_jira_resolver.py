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
        self.mock_redis.get.return_value = json.dumps(self.createmeta_response)

        self.resolver._resolve_account_id = AsyncMock(return_value="12345-abcde")

        self.rule.field_mappings.append(
            RuleFieldMapping(jira_field_id="summary", source_type=MappingSourceType.STATIC, source_value="New Hire")
        )

        payload = await self.resolver.build_payload(self.rule, self.pf_payload)

        self.assertEqual(payload["fields"]["issuetype"], {"id": "10001"})
        self.assertEqual(payload["fields"]["assignee"], {"id": "12345-abcde"})
        self.assertEqual(payload["fields"]["labels"], ["PF", "Onboarding"])
        self.assertEqual(payload["fields"]["summary"], "New Hire")

        # Verify the resolver was called with the exact extracted email
        self.resolver._resolve_account_id.assert_called_once_with("test@example.com")

    async def test_strict_validation_catches_missing_required_field(self) -> None:
        """Verifies that missing required fields raise SchemaValidationError."""
        self.createmeta_response["customfield_strict"] = {"required": True, "name": "Cost Center"}
        self.mock_redis.get.return_value = json.dumps(self.createmeta_response)

        mock_user_resp = MagicMock()
        mock_user_resp.json.return_value = [{"accountId": "12345-abcde"}]

        # 🟢 FIXED: Explicitly bind as AsyncMock
        self.mock_jira.client.get = AsyncMock(return_value=mock_user_resp)

        with self.assertRaises(SchemaValidationError):
            await self.resolver.build_payload(self.rule, self.pf_payload)

    async def test_allowed_values_mismatch(self) -> None:
        """Verifies the validator catches when a mapping uses an option Jira no longer recognizes."""
        self.createmeta_response["customfield_10045"] = {
            "fieldId": "customfield_10045",
            "required": False,
            "schema": {"type": "option"},
            "allowedValues": [{"id": "10001", "value": "Engineering"}, {"id": "10002", "value": "Human Resources"}],
        }
        self.mock_redis.get.return_value = json.dumps(self.createmeta_response)

        mock_user_resp = MagicMock()
        mock_user_resp.json.return_value = [{"accountId": "12345-abcde"}]
        mock_user_resp.raise_for_status.return_value = None

        # 🟢 FIXED: Explicitly bind as AsyncMock
        self.mock_jira.client.get = AsyncMock(return_value=mock_user_resp)

        self.rule.field_mappings.append(
            RuleFieldMapping(
                jira_field_id="customfield_10045",
                source_type=MappingSourceType.STATIC,
                source_value="Marketing",
            )
        )

        with self.assertRaises(SchemaValidationError) as context:
            await self.resolver.build_payload(self.rule, self.pf_payload)

        error_msg = str(context.exception)
        self.assertIn("customfield_10045", error_msg)
        self.assertIn("Marketing", error_msg)

    async def test_resolve_template_interpolation(self) -> None:
        """Verifies regex interpolation handles mixed types, nulls, and nested JSONPaths."""
        pf_payload = {
            "title": "Onboarding Verification",
            "metadata": {"priority_id": 1, "notes": None},
            "assignee": {"email": "test@example.com"},
        }

        res_1 = self.resolver._resolve_template("Task: {{ title }} - Assigned: {{ assignee.email }}", pf_payload)
        self.assertEqual(res_1, "Task: Onboarding Verification - Assigned: test@example.com")

        res_2 = self.resolver._resolve_template("Priority ID: {{ metadata.priority_id }}", pf_payload)
        self.assertEqual(res_2, "Priority ID: 1")

        res_3 = self.resolver._resolve_template(
            "Notes: {{ metadata.notes }} | Missing: {{ does.not.exist }}", pf_payload
        )
        self.assertEqual(res_3, "Notes:  | Missing: ")

        res_4 = self.resolver._resolve_template("Static Override", pf_payload)
        self.assertEqual(res_4, "Static Override")

    async def test_date_and_datetime_formatting(self) -> None:
        """Verifies that date fields safely coerce Python None and string 'None' to explicit JSON nulls."""
        # Inject date schemas into the mock
        self.createmeta_response["duedate"] = {"fieldId": "duedate", "required": False, "schema": {"type": "date"}}
        self.createmeta_response["customfield_10015"] = {
            "fieldId": "customfield_10015",
            "required": False,
            "schema": {"type": "datetime"},
        }
        self.mock_redis.get.return_value = json.dumps(self.createmeta_response)

        # Mock the rule to extract a dynamic date field
        self.rule.field_mappings.append(
            RuleFieldMapping(
                jira_field_id="duedate", source_type=MappingSourceType.PF_PAYLOAD, source_value="extracted_date"
            )
        )

        # Define the exact matrix of failure vectors we discovered
        test_vectors = [
            (None, None),  # Native Python None
            ("None", None),  # Template stringified None
            ("none", None),  # Lowercase text
            ("null", None),  # JSON null text
            ("", None),  # Empty string
            ("  ", None),  # Whitespace
            ("2026-02-27", "2026-02-27"),  # Valid date string
        ]

        for input_val, expected_out in test_vectors:
            with self.subTest(input_val=input_val):
                pf_payload = {"task_id": 99, "extracted_date": input_val}
                payload = await self.resolver.build_payload(self.rule, pf_payload)

                # Assert Jira gets exactly what it needs
                self.assertEqual(
                    payload["fields"].get("duedate"),
                    expected_out,
                    f"Resolver failed to safely format date input: '{input_val}'",
                )


if __name__ == "__main__":
    unittest.main()
