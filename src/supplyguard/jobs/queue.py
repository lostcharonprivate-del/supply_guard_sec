"""Background scan execution.

Scanning a full dependency tree against several external APIs takes tens of
seconds, so an HTTP request must never wait on it: the API creates a scan row,
enqueues the work and returns an id to poll.

Two execution paths, chosen at runtime:

* **arq on Redis** when Redis is reachable — the deployed configuration, where
  workers scale separately from the API.
* **an in-process asyncio task** otherwise, so that `supplyguard serve` works
  with nothing but a database. The API reports which path a scan took.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from supplyguard.config import get_settings
from supplyguard.db.session import session_scope
from supplyguard.services.scan_service import run_and_persist_scan

logger = logging.getLogger(__name__)

#: Tasks kept referenced so the event loop does not garbage-collect them
#: mid-flight, which would silently abandon a scan.
_BACKGROUND_TASKS: set[asyncio.Task] = set()


async def execute_scan_job(
    _ctx: dict | None,
    scan_id: str,
    files: dict[str, str],
    repository_url: str | None = None,
    ecosystems: list[str] | None = None,
    detectors: list[str] | None = None,
    github_token: str | None = None,
) -> dict[str, Any]:
    """Entry point for both execution paths."""
    async with session_scope() as session:
        scan = await run_and_persist_scan(
            session,
            scan_id=scan_id,
            files=files,
            repository_url=repository_url,
            ecosystems=ecosystems,
            detectors=detectors,
            github_token=github_token,
        )
        return {
            "scan_id": scan.id,
            "status": scan.status,
            "risk_score": scan.risk_score,
            "finding_count": scan.finding_count,
        }


async def enqueue_scan(
    scan_id: str,
    files: dict[str, str],
    repository_url: str | None = None,
    ecosystems: list[str] | None = None,
    detectors: list[str] | None = None,
    github_token: str | None = None,
) -> str:
    """Queue a scan. Returns the execution path taken: 'queue' or 'inline'."""
    kwargs = {
        "files": files,
        "repository_url": repository_url,
        "ecosystems": ecosystems,
        "detectors": detectors,
        "github_token": github_token,
    }
    pool = await _redis_pool()
    if pool is not None:
        try:
            await pool.enqueue_job("execute_scan_job", scan_id, **kwargs)
            return "queue"
        except Exception as exc:
            logger.warning("could not enqueue scan %s, running inline: %s", scan_id, exc)

    task = asyncio.create_task(execute_scan_job(None, scan_id, **kwargs))
    _BACKGROUND_TASKS.add(task)
    task.add_done_callback(_BACKGROUND_TASKS.discard)
    return "inline"


async def _redis_pool():
    from arq import create_pool
    from arq.connections import RedisSettings

    settings = get_settings()
    if not settings.redis_url:
        return None
    try:
        return await create_pool(RedisSettings.from_dsn(settings.redis_url))
    except Exception as exc:
        logger.info("Redis unavailable (%s); scans will run in-process.", exc)
        return None


DEFAULT_REDIS_URL = "redis://localhost:6379/0"


class _LazyRedisSettings:
    """Resolve the worker's Redis settings on access, not at import.

    arq reads `WorkerSettings.redis_settings` as a plain attribute, so the
    obvious spelling evaluates the DSN when this module is imported — which
    would make the API unimportable whenever Redis is unconfigured, defeating
    the in-process fallback this module exists to provide. A descriptor defers
    it to the moment a worker actually starts.
    """

    def __get__(self, instance: object, owner: type | None = None):
        from arq.connections import RedisSettings

        return RedisSettings.from_dsn(get_settings().redis_url or DEFAULT_REDIS_URL)


class WorkerSettings:
    """arq worker configuration. Run with `arq supplyguard.jobs.queue.WorkerSettings`."""

    functions = [execute_scan_job]
    max_jobs = 4
    #: Generous: a large monorepo scanned across four ecosystems is slow, and a
    #: job killed halfway leaves a scan stuck in `running`.
    job_timeout = 900
    keep_result = 3600
    redis_settings = _LazyRedisSettings()

    @staticmethod
    async def on_startup(ctx: dict) -> None:
        logging.basicConfig(level=logging.INFO)
        logger.info("SupplyGuard worker ready")
