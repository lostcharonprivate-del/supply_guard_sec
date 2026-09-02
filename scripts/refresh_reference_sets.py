#!/usr/bin/env python3
"""Rebuild the typosquatting reference sets from live popularity sources.

The typosquat detector compares every scanned dependency against the most
popular packages in its ecosystem. That reference set is checked into
`data/reference-sets/` so a scan needs no network to run the detector, and this
script regenerates it.

Sources (all public, no auth):

  npm       npm-high-impact, the community dataset of most-downloaded packages
  pypi      hugovk/top-pypi-packages, derived from the official BigQuery dump
  rubygems  rubygems.org's own /stats pages, ranked by downloads
  maven     Sonatype Central's browse API, ordered by namespace popularity

Usage:  python scripts/refresh_reference_sets.py [--size 2000] [--ecosystem npm]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

import httpx

OUTPUT_DIR = Path(__file__).resolve().parent.parent / "data" / "reference-sets"
TIMEOUT = httpx.Timeout(60.0)
HEADERS = {"User-Agent": "SupplyGuard reference-set builder"}


async def fetch_npm(client: httpx.AsyncClient, size: int) -> tuple[list[str], str]:
    url = "https://cdn.jsdelivr.net/npm/npm-high-impact@latest/lib/top-download.js"
    response = await client.get(url)
    response.raise_for_status()
    # The module is a single exported array of quoted package names.
    names = re.findall(r"'((?:@[^'/]+/)?[^'/\s]+)'", response.text)
    return _dedupe(names)[:size], url


async def fetch_pypi(client: httpx.AsyncClient, size: int) -> tuple[list[str], str]:
    url = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"
    response = await client.get(url, follow_redirects=True)
    response.raise_for_status()
    payload = response.json()
    rows = payload["rows"] if isinstance(payload, dict) else payload
    names = [r["project"] for r in rows if r.get("project")]
    return _dedupe(names)[:size], url


async def fetch_rubygems(client: httpx.AsyncClient, size: int) -> tuple[list[str], str]:
    """Rank gems by real download counts from the search API.

    RubyGems publishes no top-N endpoint and its /stats pages cap out at 100
    gems. The search API does return each gem's lifetime `downloads`, so a
    broad sweep of seed queries produces a genuinely download-ranked set.
    """
    url = "https://rubygems.org/api/v1/search.json"
    seeds = [chr(c) for c in range(ord("a"), ord("z") + 1)] + [
        "rails", "http", "test", "aws", "json", "api", "client", "server",
        "parser", "log", "sql", "auth", "cache", "config", "util", "rack",
        "ruby", "gem", "web", "data", "file", "time", "string", "core",
    ]
    downloads: dict[str, int] = {}
    for seed in seeds:
        for page in (1, 2, 3):
            try:
                response = await client.get(url, params={"query": seed, "page": page})
            except httpx.HTTPError:
                break
            if response.status_code != 200:
                break
            gems = response.json()
            if not gems:
                break
            for gem in gems:
                name, count = gem.get("name"), gem.get("downloads")
                if name and isinstance(count, int):
                    downloads[name] = max(downloads.get(name, 0), count)
            await asyncio.sleep(0.15)  # be a good citizen
    ranked = sorted(downloads, key=lambda n: -downloads[n])
    return _dedupe(ranked)[:size], url


async def fetch_maven(client: httpx.AsyncClient, size: int) -> tuple[list[str], str]:
    url = "https://central.sonatype.com/api/internal/browse/components"
    names: list[str] = []
    page = 0
    # The browse API rejects a page size above 20.
    while len(names) < size and page < 200:
        response = await client.post(
            url,
            json={
                "page": page,
                "size": 20,
                "sortField": "nsPopularityAppCount",
                "sortDirection": "desc",
            },
        )
        if response.status_code != 200:
            break
        components = response.json().get("components") or []
        if not components:
            break
        names.extend(
            f"{c['namespace']}:{c['name']}"
            for c in components
            if c.get("namespace") and c.get("name")
        )
        page += 1
        await asyncio.sleep(0.3)
    return _dedupe(names)[:size], url


FETCHERS = {
    "npm": fetch_npm,
    "pypi": fetch_pypi,
    "rubygems": fetch_rubygems,
    "maven": fetch_maven,
}


def _dedupe(names: list[str]) -> list[str]:
    """Preserve rank order while removing duplicates and obvious junk."""
    seen: set[str] = set()
    out: list[str] = []
    for name in names:
        cleaned = name.strip()
        if not cleaned or cleaned in seen or cleaned.startswith("."):
            continue
        seen.add(cleaned)
        out.append(cleaned)
    return out


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--size", type=int, default=2000, help="packages per ecosystem")
    parser.add_argument("--ecosystem", choices=sorted(FETCHERS), help="only this one")
    args = parser.parse_args()

    targets = [args.ecosystem] if args.ecosystem else sorted(FETCHERS)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    failures = 0

    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as client:
        for ecosystem in targets:
            try:
                names, source = await FETCHERS[ecosystem](client, args.size)
            except Exception as exc:
                print(f"  {ecosystem:9s} FAILED: {exc}", file=sys.stderr)
                failures += 1
                continue
            if not names:
                print(f"  {ecosystem:9s} FAILED: source returned no packages", file=sys.stderr)
                failures += 1
                continue

            path = OUTPUT_DIR / f"{ecosystem}.json"
            path.write_text(
                json.dumps(
                    {
                        "ecosystem": ecosystem,
                        "generated_at": datetime.now(UTC).isoformat(),
                        "source": source,
                        "count": len(names),
                        # Rank order is meaningful: index 0 is the most popular,
                        # and the detector uses rank to weight confidence.
                        "packages": names,
                    },
                    indent=1,
                )
                + "\n"
            )
            print(f"  {ecosystem:9s} {len(names):5d} packages -> {path.relative_to(Path.cwd()) if path.is_relative_to(Path.cwd()) else path}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
