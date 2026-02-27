import html
import json
import re
import time
from collections.abc import Awaitable, Callable
from typing import Any

from loguru import logger
from markupsafe import Markup
from redis.asyncio import Redis


def generate_highlighted_json(data: dict[str, Any]) -> Markup:
    """Transforms a Python dictionary into syntax-highlighted HTML.

    Relies on Bulma typography classes to avoid frontend JS highlighting libraries.
    """
    safe_str = html.escape(json.dumps(data, indent=2))

    def replacer(match: re.Match) -> str:
        token = match.group(0)
        # Identify Keys (Ends with a colon)
        if token.endswith(":"):
            key = token[:-1].rstrip()
            return f'<span class="has-text-info-light">{key}</span>:'
        # Identify String Values
        elif token.startswith("&quot;"):
            return f'<span class="has-text-success-light">{token}</span>'
        # Identify Null
        elif token == "null":
            return f'<span class="has-text-danger-light">{token}</span>'
        # Identify Numbers & Booleans
        else:
            return f'<span class="has-text-warning">{token}</span>'

    # Regex matches: Keys (with colon) | Strings | Primitives (true, false, null, numbers)
    pattern = re.compile(
        r"&quot;(?:\\&quot;|.)*?&quot;\s*:|&quot;(?:\\&quot;|.)*?&quot;|\b(?:true|false|null|\d+(?:\.\d+)?)\b"
    )
    highlighted = pattern.sub(replacer, safe_str)

    return Markup(highlighted)


class CacheManager:
    """Manages Stale-While-Revalidate (SWR) logic for ephemeral metadata."""

    def __init__(self, redis_client: Redis, ttl_seconds: int = 604800) -> None:
        """
        Args:
            redis_client: Active asynchronous Redis connection.
            ttl_seconds: Hard expiration for cache keys (default: 7 days).
        """
        self.redis = redis_client
        self.ttl = ttl_seconds

    async def get_swr(self, key: str, fetch_func: Callable[[], Awaitable[Any]]) -> Any:
        """Retrieves data from cache, falling back to a live fetch on miss.

        Args:
            key: The exact Redis key to query.
            fetch_func: An asynchronous callable that returns the raw data if the cache is cold.

        Returns:
            Any: The deserialized data.
        """
        cached_data = await self.redis.get(key)
        if cached_data:
            return json.loads(cached_data)

        logger.info(f"Cache miss for {key}. Executing blocking live fetch.")
        live_data = await fetch_func()

        await self.redis.setex(key, self.ttl, json.dumps(live_data))
        return live_data


def profile_block(name: str):
    """Measures wall-clock execution time of a code block."""
    start_time = time.perf_counter()
    yield
    elapsed = time.perf_counter() - start_time
    logger.debug(f"[PROFILER] {name} completed in {elapsed:.4f} seconds")
