import asyncio
import unittest
from unittest.mock import AsyncMock

from src.core.clients import HTTPClientManager


class TestHTTPClientManager(unittest.IsolatedAsyncioTestCase):
    """Test suite for the thread-safe HTTP connection pool manager."""

    async def asyncTearDown(self) -> None:
        """Ensures the global state is purged after each test."""
        await HTTPClientManager.teardown()

    def test_get_client_enforces_singleton_by_base_url(self) -> None:
        """Verifies that multiple requests for the same domain yield the exact same memory reference."""
        url = "https://api.peopleforce.io"

        client_a = HTTPClientManager.get_client(url, headers={}, auth=None)
        client_b = HTTPClientManager.get_client(url, headers={"X-API-KEY": "123"}, auth=None)

        self.assertIs(client_a, client_b, "Manager instantiated multiple connection pools for the same domain.")

    def test_get_client_isolates_different_domains(self) -> None:
        """Verifies that different domains receive distinct connection pools."""
        pf_client = HTTPClientManager.get_client("https://app.peopleforce.io", headers={}, auth=None)
        jira_client = HTTPClientManager.get_client("https://todapay.atlassian.net", headers={}, auth=None)

        self.assertIsNot(
            pf_client, jira_client, "Manager incorrectly shared a connection pool across different domains."
        )

    async def test_teardown_closes_all_transports(self) -> None:
        """Verifies that teardown cascades the aclose() command to all active transports."""
        pf_client = HTTPClientManager.get_client("https://app.peopleforce.io", headers={}, auth=None)
        jira_client = HTTPClientManager.get_client("https://todapay.atlassian.net", headers={}, auth=None)

        # Intercept the underlying close methods
        pf_client.aclose = AsyncMock()
        jira_client.aclose = AsyncMock()

        await HTTPClientManager.teardown()

        pf_client.aclose.assert_awaited_once()
        jira_client.aclose.assert_awaited_once()

        self.assertEqual(len(HTTPClientManager._clients), 0, "Manager dictionary was not cleared after teardown.")

    async def test_thread_safety_under_load(self) -> None:
        """Verifies that highly concurrent requests do not bypass the dictionary lock."""
        # Force a clean slate
        await HTTPClientManager.teardown()

        url = "https://race.condition.test"

        # Define a blocking wrapper to force concurrent evaluation
        async def fetch_client():
            # A tiny sleep forces the event loop to yield, exacerbating TOCTOU vulnerabilities
            await asyncio.sleep(0.01)
            return HTTPClientManager.get_client(url, headers={}, auth=None)

        # Fire 50 concurrent instantiation requests
        tasks = [fetch_client() for _ in range(50)]
        results = await asyncio.gather(*tasks)

        # Assert that despite 50 concurrent requests, only exactly 1 client was ever created
        self.assertEqual(len(HTTPClientManager._clients), 1)

        # Assert that all 50 returned references point to the exact same object
        primary_reference = results[0]
        for client in results:
            self.assertIs(client, primary_reference)


if __name__ == "__main__":
    unittest.main()
