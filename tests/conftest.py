"""Shared fixtures.

The unit suite runs entirely offline: parsers are pure, and detectors that
need registry data are given a stub adapter or a pre-populated metadata cache.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from supplyguard.clients.http import HttpClient
from supplyguard.core.types import DependencyGraph, PackageMetadata, ResolvedPackage
from supplyguard.detectors.base import DetectorConfig, MetadataProvider, ScanContext
from supplyguard.ecosystems import get_adapter

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


def load_fixture(*parts: str) -> str:
    return (FIXTURES.joinpath(*parts)).read_text()


class StubMetadataProvider(MetadataProvider):
    """A MetadataProvider pre-loaded with canned registry responses.

    Lets detector behaviour be tested against exact metadata — a package that
    is three days old with two downloads — without touching the network.
    """

    def __init__(self, adapter, entries: dict[str, PackageMetadata] | None = None) -> None:
        super().__init__(adapter, http=None)  # type: ignore[arg-type]
        self._entries = {
            adapter.normalize_name(k): v for k, v in (entries or {}).items()
        }
        self.requested: list[str] = []

    async def get(self, name: str) -> PackageMetadata | None:
        self.requested.append(name)
        return self._entries.get(self.adapter.normalize_name(name))

    async def get_many(self, names: list[str]) -> dict[str, PackageMetadata]:
        out: dict[str, PackageMetadata] = {}
        for name in names:
            meta = await self.get(name)
            if meta is not None:
                out[self.adapter.normalize_name(name)] = meta
        return out

    async def downloads(self, name: str) -> int | None:
        meta = self._entries.get(self.adapter.normalize_name(name))
        return meta.downloads_last_month if meta else None


def make_context(
    ecosystem: str,
    packages: list[tuple[str, str]] | list[ResolvedPackage],
    *,
    metadata: dict[str, PackageMetadata] | None = None,
    config: DetectorConfig | None = None,
    registry_configs: dict[str, str] | None = None,
) -> ScanContext:
    """Build a ScanContext for detector tests without any network."""
    adapter = get_adapter(ecosystem)
    graph = DependencyGraph(ecosystem=ecosystem, manifest_filename="test-manifest")
    for entry in packages:
        if isinstance(entry, ResolvedPackage):
            graph.add(entry)
        else:
            name, version = entry
            graph.add(
                ResolvedPackage(
                    ecosystem=ecosystem, name=name, version=version, depth=0, is_direct=True
                )
            )
    return ScanContext(
        adapter=adapter,
        graph=graph,
        http=None,  # type: ignore[arg-type]
        metadata=StubMetadataProvider(adapter, metadata),
        config=config or DetectorConfig(),
        registry_configs=registry_configs or {},
    )


@pytest.fixture
def http_client() -> HttpClient:
    return HttpClient()
