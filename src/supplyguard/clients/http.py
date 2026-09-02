"""Cached, rate-limited async HTTP client shared by every external integration.

Registries and vulnerability databases all have generous but finite limits, and
a single scan of a real lockfile fans out to hundreds of calls. Every request
goes through one place so that caching, throttling, retries and metrics are
uniform and impossible to forget at a call-site.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import random
import time
from dataclasses import dataclass, field
from types import TracebackType
from typing import Any
from urllib.parse import urlsplit

import httpx

from supplyguard.clients.cache import Cache, MemoryCache

logger = logging.getLogger(__name__)

# Sentinel stored in the cache so that 404s are cached too. Re-asking a registry
# about a package that does not exist is the single most common wasted call.
_NOT_FOUND = {"__sg_not_found__": True}


class RateLimiter:
    """Token bucket: `rate` requests/second with a burst allowance."""

    def __init__(self, rate: float, burst: int | None = None) -> None:
        self.rate = rate
        self.capacity = burst if burst is not None else max(1, int(rate))
        self._tokens = float(self.capacity)
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                self._tokens = min(
                    self.capacity, self._tokens + (now - self._updated) * self.rate
                )
                self._updated = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                await asyncio.sleep((1.0 - self._tokens) / self.rate)


@dataclass
class HttpStats:
    requests: int = 0
    cache_hits: int = 0
    errors: int = 0
    retries: int = 0
    not_found: int = 0
    by_host: dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "requests": self.requests,
            "cache_hits": self.cache_hits,
            "errors": self.errors,
            "retries": self.retries,
            "not_found": self.not_found,
            "by_host": dict(self.by_host),
        }


class HttpError(RuntimeError):
    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class HttpClient:
    """Async HTTP with per-host rate limiting, response caching and retries."""

    #: Conservative defaults; overridable via settings.
    DEFAULT_RATES: dict[str, float] = {
        "api.osv.dev": 20.0,
        "registry.npmjs.org": 15.0,
        "api.npmjs.org": 8.0,
        "pypi.org": 15.0,
        "rubygems.org": 8.0,
        "search.maven.org": 4.0,
        "api.github.com": 8.0,
        "api.deps.dev": 10.0,
    }
    FALLBACK_RATE = 5.0

    def __init__(
        self,
        cache: Cache | None = None,
        *,
        timeout: float = 15.0,
        max_retries: int = 3,
        user_agent: str = "SupplyGuard/0.1 (+https://github.com/supplyguard)",
        rates: dict[str, float] | None = None,
        max_concurrency: int = 16,
        default_headers: dict[str, str] | None = None,
    ) -> None:
        self.cache: Cache = cache or MemoryCache()
        self.max_retries = max_retries
        self.stats = HttpStats()
        self._rates = {**self.DEFAULT_RATES, **(rates or {})}
        self._limiters: dict[str, RateLimiter] = {}
        self._sem = asyncio.Semaphore(max_concurrency)
        headers = {"User-Agent": user_agent, "Accept": "application/json"}
        headers.update(default_headers or {})
        self._client = httpx.AsyncClient(
            # Split rather than a single value: registries occasionally accept a
            # connection and then stall, and waiting the full read budget to
            # discover that wastes the whole scan's latency.
            timeout=httpx.Timeout(timeout, connect=min(5.0, timeout), pool=min(5.0, timeout)),
            headers=headers,
            follow_redirects=True,
            limits=httpx.Limits(max_connections=max_concurrency),
        )

    # -- lifecycle ----------------------------------------------------------
    async def __aenter__(self) -> HttpClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    # -- internals ----------------------------------------------------------
    def _limiter(self, host: str) -> RateLimiter:
        if host not in self._limiters:
            self._limiters[host] = RateLimiter(self._rates.get(host, self.FALLBACK_RATE))
        return self._limiters[host]

    @staticmethod
    def _cache_key(method: str, url: str, body: Any | None) -> str:
        raw = f"{method}:{url}:{json.dumps(body, sort_keys=True) if body else ''}"
        return "http:" + hashlib.sha256(raw.encode()).hexdigest()[:40]

    async def _request(
        self,
        method: str,
        url: str,
        *,
        json_body: Any | None = None,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        ttl: int = 86_400,
        cacheable: bool = True,
        allow_404: bool = True,
    ) -> Any | None:
        host = urlsplit(url).netloc
        full = str(httpx.URL(url, params=params)) if params else url
        key = self._cache_key(method, full, json_body)

        if cacheable and ttl > 0:
            cached = await self.cache.get(key)
            if cached is not None:
                self.stats.cache_hits += 1
                return None if cached == _NOT_FOUND else cached

        await self._limiter(host).acquire()

        last_error: Exception | None = None
        for attempt in range(self.max_retries + 1):
            try:
                async with self._sem:
                    self.stats.requests += 1
                    self.stats.by_host[host] = self.stats.by_host.get(host, 0) + 1
                    response = await self._client.request(
                        method, url, json=json_body, params=params, headers=headers
                    )

                if response.status_code == 404 and allow_404:
                    self.stats.not_found += 1
                    if cacheable and ttl > 0:
                        # Cache negatives for a shorter window: a package that
                        # does not exist today may be published tomorrow, and
                        # that transition is exactly a dependency-confusion event.
                        await self.cache.set(key, _NOT_FOUND, min(ttl, 3600))
                    return None

                if response.status_code in (429, 502, 503, 504):
                    raise HttpError(
                        f"{response.status_code} from {host}", response.status_code
                    )

                response.raise_for_status()
                data = response.json() if response.content else None

                if cacheable and ttl > 0 and data is not None:
                    await self.cache.set(key, data, ttl)
                return data

            except (httpx.HTTPError, HttpError, json.JSONDecodeError) as exc:
                last_error = exc
                status = getattr(exc, "status_code", None) or getattr(
                    getattr(exc, "response", None), "status_code", None
                )
                # 4xx other than the throttling code will not improve on retry.
                if status and 400 <= status < 500 and status != 429:
                    self.stats.errors += 1
                    raise HttpError(f"{method} {url} failed: {exc}", status) from exc
                if attempt >= self.max_retries:
                    break
                self.stats.retries += 1
                backoff = min(8.0, 0.4 * (2**attempt)) + random.uniform(0, 0.3)
                logger.debug("retry %s %s in %.2fs (%s)", method, url, backoff, exc)
                await asyncio.sleep(backoff)

        self.stats.errors += 1
        raise HttpError(f"{method} {url} failed after retries: {last_error}")

    # -- public API ---------------------------------------------------------
    async def get_json(self, url: str, **kwargs: Any) -> Any | None:
        return await self._request("GET", url, **kwargs)

    async def post_json(self, url: str, body: Any, **kwargs: Any) -> Any | None:
        return await self._request("POST", url, json_body=body, **kwargs)

    async def gather(self, coros: list[Any], *, chunk: int = 32) -> list[Any]:
        """Run coroutines with bounded concurrency, returning exceptions inline."""
        from supplyguard.utils.concurrency import gather_bounded

        return await gather_bounded(coros, chunk=chunk)
