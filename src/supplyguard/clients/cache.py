"""Cache backends for external API responses.

Two implementations behind one protocol: Redis for the deployed service,
an in-process LRU for tests and the standalone CLI. Nothing else in the
codebase knows which one it is talking to.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections import OrderedDict
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class Cache(Protocol):
    async def get(self, key: str) -> Any | None: ...
    async def set(self, key: str, value: Any, ttl: int) -> None: ...
    async def delete(self, key: str) -> None: ...
    async def close(self) -> None: ...


class MemoryCache:
    """Bounded in-process cache with TTL. Used by the CLI and the test-suite."""

    def __init__(self, max_entries: int = 20_000) -> None:
        self._data: OrderedDict[str, tuple[float, Any]] = OrderedDict()
        self._max = max_entries
        self._lock = asyncio.Lock()
        self.hits = 0
        self.misses = 0

    async def get(self, key: str) -> Any | None:
        async with self._lock:
            entry = self._data.get(key)
            if entry is None:
                self.misses += 1
                return None
            expires_at, value = entry
            if expires_at < time.time():
                del self._data[key]
                self.misses += 1
                return None
            self._data.move_to_end(key)
            self.hits += 1
            return value

    async def set(self, key: str, value: Any, ttl: int) -> None:
        async with self._lock:
            self._data[key] = (time.time() + ttl, value)
            self._data.move_to_end(key)
            while len(self._data) > self._max:
                self._data.popitem(last=False)

    async def delete(self, key: str) -> None:
        async with self._lock:
            self._data.pop(key, None)

    async def close(self) -> None:
        self._data.clear()


class RedisCache:
    """Redis-backed cache. Values are JSON-serialised."""

    def __init__(self, url: str, namespace: str = "sg") -> None:
        import redis.asyncio as aioredis

        self._redis = aioredis.from_url(url, decode_responses=True)
        self._ns = namespace
        self.hits = 0
        self.misses = 0

    def _k(self, key: str) -> str:
        return f"{self._ns}:{key}"

    async def get(self, key: str) -> Any | None:
        raw = await self._redis.get(self._k(key))
        if raw is None:
            self.misses += 1
            return None
        self.hits += 1
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None

    async def set(self, key: str, value: Any, ttl: int) -> None:
        await self._redis.set(self._k(key), json.dumps(value, default=str), ex=ttl)

    async def delete(self, key: str) -> None:
        await self._redis.delete(self._k(key))

    async def close(self) -> None:
        await self._redis.aclose()


class NullCache:
    """Disables caching. Useful when a scan must reflect live registry state."""

    hits = 0
    misses = 0

    async def get(self, key: str) -> Any | None:
        return None

    async def set(self, key: str, value: Any, ttl: int) -> None:
        return None

    async def delete(self, key: str) -> None:
        return None

    async def close(self) -> None:
        return None


async def build_cache(redis_url: str | None) -> Cache:
    """Return a Redis cache when reachable, otherwise fall back to memory.

    The fallback keeps `supplyguard scan` usable as a single binary with no
    infrastructure, which is how most reviewers will first run this.
    """
    if not redis_url:
        return MemoryCache()
    try:
        cache = RedisCache(redis_url)
        await cache._redis.ping()
        return cache
    except Exception:
        return MemoryCache()
