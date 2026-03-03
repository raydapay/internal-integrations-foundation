import unittest

from src.domain.pf_jira.resolver import format_html_to_adf


class TestPeopleForceADFParser(unittest.TestCase):
    """
    Verifies the structural translation of PeopleForce HTML payloads
    into Atlassian Document Format (ADF) compatible with Jira REST API v3.
    """

    # === CHANGED BLOCK ===
    def test_nbsp_resolution_and_newlines(self) -> None:
        """
        Ensures &nbsp; is converted to native \\xa0 to preserve Jira spacing,
        and <br> tags result in hardBreak ADF nodes.
        """
        html = 'Line 1&nbsp;<br id="isPasted"><br>Line 2'
        adf = format_html_to_adf(html)

        paragraph_content = adf["content"][0]["content"]

        # Verify '&nbsp;' became a native non-breaking space (\xa0) instead of standard space
        self.assertEqual(paragraph_content[0]["text"], "Line 1\xa0")

        # Verify '<br>' became a hardBreak
        self.assertEqual(paragraph_content[1]["type"], "hardBreak")
        self.assertEqual(paragraph_content[2]["type"], "hardBreak")
        self.assertEqual(paragraph_content[3]["text"], "Line 2")

    # === END CHANGED BLOCK ===

    def test_formatting_marks(self) -> None:
        """Verifies bold, italic, and underline tags map to correct ADF marks."""
        html = "<b>bold</b> and <i>italic</i>"
        adf = format_html_to_adf(html)

        content = adf["content"][0]["content"]

        self.assertEqual(content[0]["text"], "bold")
        self.assertEqual(content[0]["marks"][0]["type"], "strong")

        self.assertEqual(content[1]["text"], " and ")

        self.assertEqual(content[2]["text"], "italic")
        self.assertEqual(content[2]["marks"][0]["type"], "em")

    def test_attachment_link_stripping(self) -> None:
        """
        Verifies that authenticated <a> links drop their inner text to avoid
        duplication and generate a sanitized textual attachment placeholder.
        """
        html = (
            '<a href="https://domain.peopleforce.io/auth_link" '
            'name="Navigator(4).docx" class="fr-file">Navigator(4).docx</a>'
        )
        adf = format_html_to_adf(html)

        paragraph_content = adf["content"][0]["content"]
        self.assertEqual(len(paragraph_content), 1)
        self.assertEqual(paragraph_content[0]["text"], " [Attachment: Navigator(4).docx]")

    def test_image_tag_extraction(self) -> None:
        """Verifies that <img> tags extract the 'name' attribute into text."""
        html = '<img src="https://domain.peopleforce.io/auth_link" name="onepager.png" size="6235819">'
        adf = format_html_to_adf(html)

        paragraph_content = adf["content"][0]["content"]
        self.assertEqual(paragraph_content[0]["text"], " [Image: onepager.png]")

    def test_nested_list_structure(self) -> None:
        """Verifies strict ADF compliance for lists (bulletList -> listItem -> paragraph)."""
        html = "<ul><li>Item 1</li><li>Item 2</li></ul>"
        adf = format_html_to_adf(html)

        self.assertEqual(adf["content"][0]["type"], "bulletList")

        list_items = adf["content"][0]["content"]
        self.assertEqual(len(list_items), 2)

        self.assertEqual(list_items[0]["type"], "listItem")
        self.assertEqual(list_items[0]["content"][0]["type"], "paragraph")
        self.assertEqual(list_items[0]["content"][0]["content"][0]["text"], "Item 1")


if __name__ == "__main__":
    unittest.main()
