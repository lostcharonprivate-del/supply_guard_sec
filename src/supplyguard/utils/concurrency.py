"""Bounded concurrency helper.

Detectors need to run many coroutines at once, but they should not need an HTTP
client merely to do so — the client already enforces its own rate limits and
connection bounds. Keeping this separate means a detector can be tested with a
stubbed metadata provider and no networking objects at all.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable
from typing import Any


async def gather_bounded[T](
    coros: list[Awaitable[T]], *, chunk: int = 32
) -> list[T | BaseException]:
    """Run awaitables in fixed-size batches, returning exceptions inline.

    Exceptions are returned rather than raised so that one failed registry
    lookup does not discard the results of the other thirty-one.
    """
    results: list[Any] = []
    for start in range(0, len(coros), chunk):
        batch = coros[start : start + chunk]
        results.extend(await asyncio.gather(*batch, return_exceptions=True))
    return results
