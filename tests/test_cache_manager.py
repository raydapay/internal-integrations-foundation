import json
import unittest
from unittest.mock import AsyncMock

from src.core.utils import CacheManager


class TestCacheManager(unittest.IsolatedAsyncioTestCase):
    """Test suite for the Stale-While-Revalidate metadata cache wrapper."""

    async def test_get_swr_cache_hit(self) -> None:
        """Verifies that a valid Redis key returns instantly without invoking the API callable."""
        mock_redis = AsyncMock()
        mock_redis.get.return_value = json.dumps([{"key": "IT", "name": "Information Tech"}])
        mock_fetch = AsyncMock()

        cache = CacheManager(mock_redis)
        result = await cache.get_swr("jira:projects", mock_fetch)

        self.assertEqual(result[0]["key"], "IT")
        mock_fetch.assert_not_called()
        mock_redis.setex.assert_not_called()

    async def test_get_swr_cache_miss(self) -> None:
        """Verifies that a missing key invokes the callable, caches the result, and returns the live data."""
        mock_redis = AsyncMock()
        mock_redis.get.return_value = None
        mock_fetch = AsyncMock(return_value={"10001": "Task"})

        cache = CacheManager(mock_redis)
        result = await cache.get_swr("jira:issuetypes", mock_fetch)

        self.assertEqual(result["10001"], "Task")
        mock_fetch.assert_awaited_once()
        mock_redis.setex.assert_awaited_once_with("jira:issuetypes", 604800, '{"10001": "Task"}')


if __name__ == "__main__":
    unittest.main()
