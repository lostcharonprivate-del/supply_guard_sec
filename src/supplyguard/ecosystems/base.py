"""The ecosystem plugin interface.

Adding a fifth ecosystem (Go modules, crates.io, ...) means writing one module
that subclasses :class:`EcosystemAdapter` and decorating it with
:func:`register`. No core module, detector or API route needs to change:
everything downstream consumes the adapter through this interface only.
"""

from __future__ import annotations

import fnmatch
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, ClassVar

from supplyguard.core.types import DependencyGraph, PackageMetadata

if TYPE_CHECKING:  # pragma: no cover
    from supplyguard.clients.http import HttpClient


class ManifestParseError(ValueError):
    """Raised when a manifest is malformed or not what its filename claims."""


class EcosystemAdapter(ABC):
    """One package ecosystem: how to parse its lockfiles and query its registry."""

    # --- Identity -----------------------------------------------------------
    name: ClassVar[str]
    display_name: ClassVar[str]
    #: Ecosystem string used by the OSV.dev API.
    osv_ecosystem: ClassVar[str]
    #: Ecosystem enum used by the GitHub Advisory GraphQL API.
    ghsa_ecosystem: ClassVar[str]
    #: Glob patterns for the manifests/lockfiles this adapter understands.
    manifest_patterns: ClassVar[tuple[str, ...]] = ()
    #: Lockfiles carry a fully resolved tree; plain manifests do not.
    lockfile_patterns: ClassVar[tuple[str, ...]] = ()
    #: Registry config files inspected by the dependency-confusion detector.
    registry_config_patterns: ClassVar[tuple[str, ...]] = ()
    #: What :meth:`fetch_download_count` actually returns. RubyGems only
    #: publishes lifetime totals, which are ~50x a monthly figure, so callers
    #: must scale their thresholds rather than compare across ecosystems naively.
    download_metric: ClassVar[str] = "monthly"  # "monthly" | "lifetime" | "none"
    #: True when the ecosystem has namespaces that can be claimed (npm @scope,
    #: Maven groupId). Drives scope-squatting checks.
    supports_scopes: ClassVar[bool] = False

    # --- Naming -------------------------------------------------------------
    def normalize_name(self, name: str) -> str:
        """Canonical form used as the cache/comparison key."""
        return name.strip().lower()

    def scope_of(self, name: str) -> str | None:
        """Namespace portion of a package name, if the ecosystem has one."""
        return None

    def display_of(self, name: str) -> str:
        """Human-facing name (adapters may prefer the registry's own casing)."""
        return name

    # --- Manifests ----------------------------------------------------------
    @classmethod
    def supports_manifest(cls, filename: str) -> bool:
        base = filename.rsplit("/", 1)[-1]
        return any(fnmatch.fnmatch(base, p) for p in cls.manifest_patterns)

    @classmethod
    def is_lockfile(cls, filename: str) -> bool:
        base = filename.rsplit("/", 1)[-1]
        return any(fnmatch.fnmatch(base, p) for p in cls.lockfile_patterns)

    @abstractmethod
    def parse_manifest(self, content: str, filename: str) -> DependencyGraph:
        """Parse a manifest into a resolved dependency graph.

        Implementations must be pure: no network, no I/O. That is what makes
        the parsers cheap to unit-test against real-world lockfile fixtures.
        """

    # --- Registry -----------------------------------------------------------
    @abstractmethod
    async def fetch_metadata(self, name: str, http: HttpClient) -> PackageMetadata:
        """Fetch and normalise registry metadata for a package.

        Must return ``PackageMetadata(exists=False)`` rather than raising when
        the registry reports a 404 — "this package does not exist publicly" is
        a meaningful answer for the dependency-confusion detector.
        """

    async def fetch_download_count(self, name: str, http: HttpClient) -> int | None:
        """Monthly downloads, when the registry exposes them. None = unknown."""
        return None

    @abstractmethod
    def registry_package_url(self, name: str) -> str:
        """Human-browsable registry page for a package."""

    # --- Versions -----------------------------------------------------------
    @abstractmethod
    def parse_version(self, version: str) -> tuple:
        """Return a sortable key for a version string.

        Only used for staleness ("is there something newer?"). Vulnerable-range
        matching is delegated to OSV, which implements each ecosystem's real
        range semantics.
        """

    def compare_versions(self, a: str, b: str) -> int:
        ka, kb = self.parse_version(a), self.parse_version(b)
        return (ka > kb) - (ka < kb)

    # --- Heuristics ---------------------------------------------------------
    def looks_private(self, name: str) -> bool:
        """Whether a name looks like an internal/private package.

        Overridden per ecosystem; the dependency-confusion detector combines
        this with registry-config evidence before flagging anything.
        """
        return False


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------

_ADAPTERS: dict[str, EcosystemAdapter] = {}


def register(cls: type[EcosystemAdapter]) -> type[EcosystemAdapter]:
    """Class decorator that adds an adapter to the global registry."""
    instance = cls()
    _ADAPTERS[cls.name] = instance
    return cls


def get_adapter(name: str) -> EcosystemAdapter:
    _load_builtin_adapters()
    try:
        return _ADAPTERS[name.lower()]
    except KeyError:
        raise KeyError(
            f"Unknown ecosystem {name!r}. Available: {sorted(_ADAPTERS)}"
        ) from None


def all_adapters() -> list[EcosystemAdapter]:
    _load_builtin_adapters()
    return [_ADAPTERS[k] for k in sorted(_ADAPTERS)]


def ecosystem_names() -> list[str]:
    return [a.name for a in all_adapters()]


def adapter_for_osv_ecosystem(ecosystem: str) -> EcosystemAdapter | None:
    """Resolve an adapter from an OSV ecosystem string (`npm`, `PyPI`, `Maven`).

    OSV also emits suffixed variants such as `Alpine:v3.18`, so only the part
    before the first colon is significant.
    """
    _load_builtin_adapters()
    head = (ecosystem or "").split(":")[0].strip().lower()
    for adapter in _ADAPTERS.values():
        if adapter.osv_ecosystem.lower() == head or adapter.name == head:
            return adapter
    return None


def adapter_for_manifest(filename: str) -> EcosystemAdapter | None:
    """Pick the adapter that understands a given manifest filename."""
    _load_builtin_adapters()
    base = filename.rsplit("/", 1)[-1]
    candidates = [a for a in all_adapters() if a.supports_manifest(base)]
    if not candidates:
        return None
    # Prefer an adapter that treats the file as a lockfile: a resolved tree
    # always beats a declaration-only manifest.
    candidates.sort(key=lambda a: (not a.is_lockfile(base), a.name))
    return candidates[0]


_loaded = False


def _load_builtin_adapters() -> None:
    """Import the built-in adapter modules exactly once.

    Kept lazy so that ``supplyguard.ecosystems.base`` stays import-cycle free.
    """
    global _loaded
    if _loaded:
        return
    _loaded = True
    from supplyguard.ecosystems import maven, npm, pypi, rubygems  # noqa: F401
