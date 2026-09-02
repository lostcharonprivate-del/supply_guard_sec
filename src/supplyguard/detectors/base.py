"""The detection engine interface.

Every detector consumes a :class:`ScanContext` and returns
:class:`~supplyguard.core.types.Finding` objects. Detectors never talk to the
database, never touch HTTP directly except through the shared client, and never
know about each other — which is what makes each one independently testable
against a hand-built context.
"""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import ClassVar

from supplyguard.clients.http import HttpClient
from supplyguard.core.types import (
    DependencyGraph,
    Finding,
    FindingCategory,
    PackageMetadata,
    ResolvedPackage,
)
from supplyguard.ecosystems.base import EcosystemAdapter

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class DetectorConfig:
    """Tunable thresholds.

    Every heuristic threshold in the system lives here rather than as a literal
    buried in a detector, so that the false-positive posture can be tuned (and
    documented) in one place.
    """

    # --- typosquatting ---
    max_edit_distance: int = 2
    typosquat_min_name_length: int = 4
    #: A package must be below this monthly download count to be considered a
    #: plausible squat rather than a coincidentally similar popular package.
    typosquat_max_downloads: int = 25_000
    #: ...or younger than this many days.
    typosquat_max_age_days: int = 365
    #: Reference-set size per ecosystem. The shipped sets hold 2,000 names;
    #: truncating below that silently drops real targets (`cross-env` sits at
    #: rank 1,930 by downloads, and `crossenv` was a real 2017 npm attack).
    reference_set_size: int = 2000

    # --- malicious heuristics ---
    new_package_age_days: int = 60
    low_download_threshold: int = 1_000
    short_readme_length: int = 200
    maintainer_change_window_days: int = 90

    # --- staleness ---
    stale_major_versions_behind: int = 1
    stale_days_behind: int = 730

    # --- dependency confusion ---
    #: Extra names to treat as private, beyond adapter heuristics.
    internal_name_patterns: tuple[str, ...] = ()
    organization_scopes: tuple[str, ...] = ()

    # --- general ---
    #: Skip registry metadata lookups for packages deeper than this. Keeps a
    #: 5,000-package monorepo scan from making 5,000 registry calls when the
    #: heuristics matter most for shallow, recently-added dependencies.
    metadata_max_depth: int = 99
    max_metadata_lookups: int = 800


class MetadataProvider:
    """Deduplicated, concurrency-safe registry metadata access for one scan.

    The typosquat, malicious and dependency-confusion detectors all want
    metadata for overlapping sets of packages. Routing every lookup through one
    memoized provider means each package is fetched at most once per scan, on
    top of whatever the HTTP cache already serves.
    """

    def __init__(self, adapter: EcosystemAdapter, http: HttpClient, *, budget: int = 800) -> None:
        self.adapter = adapter
        self.http = http
        self._cache: dict[str, PackageMetadata] = {}
        self._downloads: dict[str, int | None] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._budget = budget
        self.lookups = 0
        self.budget_exhausted = False

    def _lock(self, key: str) -> asyncio.Lock:
        if key not in self._locks:
            self._locks[key] = asyncio.Lock()
        return self._locks[key]

    async def get(self, name: str) -> PackageMetadata | None:
        key = self.adapter.normalize_name(name)
        if key in self._cache:
            return self._cache[key]
        async with self._lock(key):
            if key in self._cache:
                return self._cache[key]
            if self.lookups >= self._budget:
                self.budget_exhausted = True
                return None
            self.lookups += 1
            try:
                metadata = await self.adapter.fetch_metadata(name, self.http)
            except Exception as exc:
                logger.warning("metadata lookup failed for %s: %s", name, exc)
                return None
            self._cache[key] = metadata
            return metadata

    async def get_many(self, names: list[str]) -> dict[str, PackageMetadata]:
        unique = list(dict.fromkeys(names))
        results = await self.http.gather([self.get(n) for n in unique])
        out: dict[str, PackageMetadata] = {}
        for name, result in zip(unique, results, strict=False):
            if isinstance(result, PackageMetadata):
                out[self.adapter.normalize_name(name)] = result
        return out

    async def downloads(self, name: str) -> int | None:
        key = self.adapter.normalize_name(name)
        if key in self._downloads:
            return self._downloads[key]
        try:
            value = await self.adapter.fetch_download_count(name, self.http)
        except Exception:
            value = None
        self._downloads[key] = value
        return value

    def cached(self, name: str) -> PackageMetadata | None:
        return self._cache.get(self.adapter.normalize_name(name))


@dataclass(slots=True)
class ScanContext:
    """Everything a detector is allowed to see."""

    adapter: EcosystemAdapter
    graph: DependencyGraph
    http: HttpClient
    metadata: MetadataProvider
    config: DetectorConfig = field(default_factory=DetectorConfig)
    #: Contents of registry/scope config files found alongside the manifest,
    #: keyed by filename (`.npmrc`, `pip.conf`, ...).
    registry_configs: dict[str, str] = field(default_factory=dict)
    #: Repository the manifest came from, when the scan started from a Git URL.
    repository_url: str | None = None
    #: Non-fatal notes surfaced to the user alongside findings.
    notes: list[str] = field(default_factory=list)

    @property
    def packages(self) -> list[ResolvedPackage]:
        return self.graph.packages

    def package_names(self) -> list[str]:
        return sorted({p.name for p in self.graph.packages})


class Detector(ABC):
    """Base class for a detection engine."""

    name: ClassVar[str]
    category: ClassVar[FindingCategory]
    #: One-line description surfaced in the API and the README threat model.
    description: ClassVar[str] = ""
    #: Documented limitations. Presented in the UI so that a reviewer of a
    #: finding knows what this detector is bad at before acting on it.
    known_false_positives: ClassVar[tuple[str, ...]] = ()
    known_false_negatives: ClassVar[tuple[str, ...]] = ()
    #: Detectors that need no network can run against a manifest alone.
    requires_network: ClassVar[bool] = True

    @abstractmethod
    async def detect(self, ctx: ScanContext) -> list[Finding]:
        """Analyse the context and return findings. Must not raise on bad data."""

    async def safe_detect(self, ctx: ScanContext) -> list[Finding]:
        """Run :meth:`detect`, converting failures into a note.

        One detector failing (a registry outage, a malformed advisory) must not
        lose the findings produced by the other four.
        """
        try:
            findings = await self.detect(ctx)
        except Exception as exc:
            logger.exception("detector %s failed", self.name)
            ctx.notes.append(f"Detector '{self.name}' failed and was skipped: {exc}")
            return []
        for finding in findings:
            finding.detector = self.name
        return findings

    def describe(self) -> dict:
        return {
            "name": self.name,
            "category": self.category.value,
            "description": self.description,
            "requires_network": self.requires_network,
            "known_false_positives": list(self.known_false_positives),
            "known_false_negatives": list(self.known_false_negatives),
        }


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------

_DETECTORS: dict[str, type[Detector]] = {}


def register_detector(cls: type[Detector]) -> type[Detector]:
    _DETECTORS[cls.name] = cls
    return cls


def all_detectors() -> list[Detector]:
    _load_builtin_detectors()
    return [_DETECTORS[k]() for k in sorted(_DETECTORS)]


def get_detector(name: str) -> Detector:
    _load_builtin_detectors()
    try:
        return _DETECTORS[name]()
    except KeyError:
        raise KeyError(f"Unknown detector {name!r}. Available: {sorted(_DETECTORS)}") from None


def detector_names() -> list[str]:
    _load_builtin_detectors()
    return sorted(_DETECTORS)


_loaded = False


def _load_builtin_detectors() -> None:
    global _loaded
    if _loaded:
        return
    _loaded = True
    from supplyguard.detectors import (  # noqa: F401
        dependency_confusion,
        malicious,
        staleness,
        typosquat,
        vulnerability,
    )
