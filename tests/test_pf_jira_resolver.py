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
        self.assertEqual(payload["fields"]["assignee"], {"accountId": "12345-abcde"})
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

    def test_format_doc(self) -> None:
        """Verifies Atlassian Document Format (ADF) generation with hard breaks."""
        text = "Line 1\nLine 2"
        res = self.resolver._format_doc(text)

        # Under the HTML parser, this should be 1 paragraph containing text -> hardBreak -> text
        self.assertEqual(len(res["content"]), 1)
        paragraph_content = res["content"][0]["content"]

        self.assertEqual(paragraph_content[0]["text"], "Line 1")
        self.assertEqual(paragraph_content[1]["type"], "hardBreak")
        self.assertEqual(paragraph_content[2]["text"], "Line 2")

    def test_format_date(self) -> None:
        """Verifies date field strict null-coercion."""
        self.assertIsNone(self.resolver._format_date(None))
        self.assertIsNone(self.resolver._format_date("None"))
        self.assertIsNone(self.resolver._format_date("null"))
        self.assertIsNone(self.resolver._format_date("  "))
        self.assertEqual(self.resolver._format_date(" 2026-02-26 "), "2026-02-26")

    def test_format_array(self) -> None:
        """Verifies array casting from strings and lists."""
        self.assertEqual(self.resolver._format_array("pf, onboarding"), ["pf", "onboarding"])
        self.assertEqual(self.resolver._format_array([1, 2, 3]), ["1", "2", "3"])
        # Should return raw object if it doesn't match expected types
        self.assertEqual(self.resolver._format_array({"key": "val"}), {"key": "val"})

    async def test_format_user(self) -> None:
        """Verifies identity resolution delegation."""
        self.resolver._resolve_account_id = AsyncMock(return_value="acc-123")

        self.assertIsNone(await self.resolver._format_user(None))
        self.assertIsNone(await self.resolver._format_user("   "))

        self.assertEqual(await self.resolver._format_user("ray@todapay.com"), {"accountId": "acc-123"})
        self.resolver._resolve_account_id.assert_called_once_with("ray@todapay.com")

    def test_validate_allowed_values_isolation(self) -> None:
        """Verifies Jira domain constraint validation."""
        schema = {"allowedValues": [{"id": "1001", "value": "Engineering"}, {"id": "1002", "value": "HR"}]}

        # Should not raise (Valid ID and Valid String)
        self.resolver._validate_allowed_values("1001", schema, "customfield_1")
        self.resolver._validate_allowed_values("HR", schema, "customfield_1")

        # Should raise SchemaValidationError
        with self.assertRaises(SchemaValidationError):
            self.resolver._validate_allowed_values("Marketing", schema, "customfield_1")

    def test_format_doc_bold_support(self) -> None:
        """Verifies that lines wrapped in asterisks are converted to strong ADF marks."""
        text = "*Bold Header*"
        res = self.resolver._format_doc(text)

        paragraph_content = res["content"][0]["content"]
        bold_node = paragraph_content[0]

        self.assertEqual(bold_node["text"], "Bold Header")
        self.assertEqual(bold_node["marks"][0]["type"], "strong")

    def test_format_doc_empty_lines(self) -> None:
        """
        Ensures empty lines (consecutive newlines) are translated to
        consecutive hardBreak nodes without violating ADF constraints.
        """
        text = "Line 1\n\nLine 2"
        res = self.resolver._format_doc(text)

        paragraph_content = res["content"][0]["content"]

        self.assertEqual(paragraph_content[0]["text"], "Line 1")
        self.assertEqual(paragraph_content[1]["type"], "hardBreak")
        self.assertEqual(paragraph_content[2]["type"], "hardBreak")
        self.assertEqual(paragraph_content[3]["text"], "Line 2")

    def test_nbsp_preservation_and_indentation(self) -> None:
        """
        Verifies that &nbsp; entities are translated to native \\xa0 characters
        and are not pruned by whitespace filters, preserving Jira indentation.
        """
        # Simulates PeopleForce sending an indented bullet point
        html = "<br>&nbsp;• HR budget<br><p>&nbsp;</p>"
        res = self.resolver._format_doc(html)

        content = res["content"]

        # Verify the first paragraph captures the \xa0 indentation
        paragraph_1 = content[0]["content"]
        self.assertEqual(paragraph_1[0]["type"], "hardBreak")

        # The exact \xa0 character must be present to force Jira UI indentation
        self.assertEqual(paragraph_1[1]["text"], "\xa0• HR budget")
        self.assertEqual(paragraph_1[2]["type"], "hardBreak")

        # Verify the isolated &nbsp; inside the <p> tag was not pruned as empty space
        paragraph_2 = content[1]["content"]
        self.assertEqual(paragraph_2[0]["text"], "\xa0")


if __name__ == "__main__":
    unittest.main()
