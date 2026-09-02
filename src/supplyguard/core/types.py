"""Core domain vocabulary.

Everything in SupplyGuard speaks these types. They are deliberately free of any
database, HTTP or framework imports so that ecosystem adapters and detectors can
be unit-tested in complete isolation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    """Ordered severity ladder shared by every detector."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> float:
        return _SEVERITY_WEIGHTS[self]

    @classmethod
    def from_cvss(cls, score: float | None) -> Severity:
        """Map a CVSS base score onto the ladder using the standard v3.1 bands."""
        if score is None:
            return cls.MEDIUM
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.INFO

    @classmethod
    def from_label(cls, label: str | None) -> Severity | None:
        if not label:
            return None
        normalised = label.strip().lower()
        aliases = {"moderate": cls.MEDIUM, "important": cls.HIGH, "none": cls.INFO}
        if normalised in aliases:
            return aliases[normalised]
        try:
            return cls(normalised)
        except ValueError:
            return None


_SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 7.5,
    Severity.MEDIUM: 4.5,
    Severity.LOW: 2.0,
    Severity.INFO: 0.5,
}

SEVERITY_ORDER: list[Severity] = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


class FindingCategory(StrEnum):
    """The polymorphic `findings` discriminator."""

    VULNERABILITY = "vulnerability"
    MALICIOUS = "malicious"
    TYPOSQUAT = "typosquat"
    DEPENDENCY_CONFUSION = "dependency_confusion"
    CI_ANOMALY = "ci_anomaly"
    STALE = "stale"


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class PackageRef:
    """A package coordinate. `version` is None when the version is unresolved."""

    ecosystem: str
    name: str
    version: str | None = None

    @property
    def key(self) -> str:
        return f"{self.ecosystem}:{self.name}@{self.version or '*'}"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.name}@{self.version}" if self.version else self.name


@dataclass(slots=True)
class ResolvedPackage:
    """One node of a resolved dependency tree.

    `depth` is 0 for the project root's direct dependencies and increases with
    each transitive hop. It feeds the risk score: a critical CVE in a direct
    dependency is more actionable than the same CVE six levels down.
    """

    ecosystem: str
    name: str
    version: str
    depth: int = 0
    is_direct: bool = False
    is_dev: bool = False
    parents: tuple[str, ...] = ()
    integrity: str | None = None
    resolved_url: str | None = None
    # Adapter-specific extras (e.g. npm `scripts`, maven `scope`).
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def ref(self) -> PackageRef:
        return PackageRef(self.ecosystem, self.name, self.version)

    @property
    def key(self) -> str:
        return f"{self.name}@{self.version}"


@dataclass(slots=True)
class DependencyGraph:
    """The parsed result of a manifest/lockfile.

    Nodes are keyed by `name@version` so that two versions of the same package
    (common in npm trees) stay distinct.
    """

    ecosystem: str
    manifest_filename: str
    nodes: dict[str, ResolvedPackage] = field(default_factory=dict)
    edges: list[tuple[str, str]] = field(default_factory=list)
    # Names declared directly in the manifest, before resolution.
    direct_names: set[str] = field(default_factory=set)
    warnings: list[str] = field(default_factory=list)

    def add(self, pkg: ResolvedPackage) -> ResolvedPackage:
        existing = self.nodes.get(pkg.key)
        if existing is None:
            self.nodes[pkg.key] = pkg
            return pkg
        # Keep the shallowest observation: a package reachable both directly and
        # transitively should be scored as direct.
        if pkg.depth < existing.depth:
            existing.depth = pkg.depth
        existing.is_direct = existing.is_direct or pkg.is_direct
        # A package is only truly dev-only if every path to it is dev.
        existing.is_dev = existing.is_dev and pkg.is_dev
        existing.parents = tuple(sorted(set(existing.parents) | set(pkg.parents)))
        return existing

    def link(self, parent_key: str, child_key: str) -> None:
        edge = (parent_key, child_key)
        if edge not in self.edges:
            self.edges.append(edge)

    @property
    def packages(self) -> list[ResolvedPackage]:
        return list(self.nodes.values())

    @property
    def direct(self) -> list[ResolvedPackage]:
        return [p for p in self.nodes.values() if p.is_direct]

    def __len__(self) -> int:
        return len(self.nodes)


@dataclass(slots=True)
class PackageMetadata:
    """Normalised registry metadata, shared shape across all ecosystems.

    Each adapter maps its registry's idiosyncratic JSON onto this so that the
    malicious/typosquat detectors never need ecosystem-specific branches.
    """

    ecosystem: str
    name: str
    exists: bool = True
    latest_version: str | None = None
    description: str | None = None
    repository_url: str | None = None
    homepage: str | None = None
    license: str | None = None
    first_published: datetime | None = None
    last_published: datetime | None = None
    version_published: dict[str, datetime] = field(default_factory=dict)
    downloads_last_month: int | None = None
    maintainers: list[str] = field(default_factory=list)
    has_readme: bool = False
    readme_length: int = 0
    # Install-time hooks, e.g. npm postinstall or a PyPI sdist with setup.py.
    install_scripts: dict[str, str] = field(default_factory=dict)
    deprecated: bool = False
    yanked: bool = False
    raw: dict[str, Any] = field(default_factory=dict)

    def published_at(self, version: str) -> datetime | None:
        return self.version_published.get(version)


@dataclass(slots=True)
class Evidence:
    """A single supporting observation behind a finding.

    Findings are only as trustworthy as their evidence; every detector must be
    able to explain *why* it fired, which is what makes false positives triable.
    """

    label: str
    detail: str
    weight: float = 0.0


@dataclass(slots=True)
class Finding:
    """The unified output of every detector."""

    category: FindingCategory
    severity: Severity
    title: str
    description: str
    package_name: str | None = None
    package_version: str | None = None
    ecosystem: str | None = None
    # Stable identity used to dedupe across re-scans, e.g. "GHSA-xxxx".
    identifier: str | None = None
    cvss_score: float | None = None
    affected_range: str | None = None
    fixed_version: str | None = None
    remediation: str | None = None
    references: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    confidence: float = 1.0
    # Depth of the offending package; used by the risk scorer.
    depth: int = 0
    is_direct: bool = False
    detector: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def dedupe_key(self) -> str:
        ident = self.identifier or self.title
        return f"{self.category}:{self.ecosystem}:{self.package_name}:{self.package_version}:{ident}"
