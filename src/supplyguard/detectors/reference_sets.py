"""Popular-package reference sets used by the typosquatting detector.

The sets are checked into `data/reference-sets/` (rebuilt by
`scripts/refresh_reference_sets.py`) so a scan needs no network to run the
typosquat detector, and so results are reproducible.

Comparing every dependency against every reference name is quadratic, so the
set is indexed on load: exact-skeleton and separator-normalised collisions
become dictionary lookups, and edit-distance candidates are narrowed by length
and character multiset before any distance is computed.
"""

from __future__ import annotations

import json
import logging
from collections import Counter, defaultdict
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from supplyguard.detectors.similarity import homoglyph_skeleton, normalise_separators

logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).resolve().parents[3] / "data" / "reference-sets"


@dataclass(frozen=True, slots=True)
class ReferencePackage:
    name: str
    #: 0 = most popular. Used to weight how attractive a target the name is.
    rank: int

    @property
    def popularity(self) -> float:
        """1.0 for the single most popular package, decaying with rank."""
        return 1.0 / (1.0 + self.rank / 200.0)


class ReferenceSet:
    """An indexed set of popular package names for one ecosystem."""

    def __init__(self, ecosystem: str, names: list[str], *, source: str = "") -> None:
        self.ecosystem = ecosystem
        self.source = source
        self.packages: list[ReferencePackage] = [
            ReferencePackage(name, rank) for rank, name in enumerate(names)
        ]
        self._by_name: dict[str, ReferencePackage] = {
            p.name.lower(): p for p in self.packages
        }
        self._by_skeleton: dict[str, list[ReferencePackage]] = defaultdict(list)
        self._by_separator: dict[str, list[ReferencePackage]] = defaultdict(list)
        self._by_length: dict[int, list[ReferencePackage]] = defaultdict(list)
        self._counters: dict[str, Counter] = {}

        for package in self.packages:
            lowered = package.name.lower()
            self._by_skeleton[homoglyph_skeleton(package.name)].append(package)
            self._by_separator[normalise_separators(package.name)].append(package)
            self._by_length[len(lowered)].append(package)
            self._counters[lowered] = Counter(lowered)

    def __len__(self) -> int:
        return len(self.packages)

    def contains(self, name: str) -> bool:
        """True when the name *is* one of the popular packages.

        This is the single most important guard in the typosquat detector: a
        package that is itself in the reference set is by definition not a
        squat of a neighbour. Without it, `preact` is permanently flagged as a
        typosquat of `react`.
        """
        return name.lower() in self._by_name

    def rank_of(self, name: str) -> int | None:
        package = self._by_name.get(name.lower())
        return package.rank if package else None

    def candidates(self, name: str, *, max_distance: int = 2) -> list[ReferencePackage]:
        """Reference packages plausibly similar to `name`.

        Cheap filters first: exact skeleton and separator collisions are hash
        lookups, and everything else is narrowed by length and character
        multiset so that expensive edit-distance work runs on a handful of
        candidates rather than the whole set.
        """
        lowered = name.lower()
        found: dict[str, ReferencePackage] = {}

        for package in self._by_skeleton.get(homoglyph_skeleton(name), ()):
            found[package.name] = package
        for package in self._by_separator.get(normalise_separators(name), ()):
            found[package.name] = package

        counter = Counter(lowered)
        length = len(lowered)
        for candidate_length in range(length - max_distance, length + max_distance + 1):
            for package in self._by_length.get(candidate_length, ()):
                other = package.name.lower()
                if other in found or other == lowered:
                    continue
                # A single edit changes the character multiset by at most 2, so
                # anything further apart cannot be within `max_distance`.
                if _multiset_distance(counter, self._counters[other]) > 2 * max_distance:
                    continue
                found[package.name] = package

        # Scoped/affixed forms differ in length by more than the bound, so
        # check the un-affixed stem separately.
        stem = normalise_separators(lowered).strip("-")
        for prefix_stripped in _stem_variants(stem):
            for package in self._by_separator.get(prefix_stripped, ()):
                found.setdefault(package.name, package)

        found.pop(lowered, None)
        return sorted(found.values(), key=lambda p: p.rank)


def _multiset_distance(a: Counter, b: Counter) -> int:
    """Total character insertions + deletions between two multisets."""
    return sum(((a - b) + (b - a)).values())


def _stem_variants(stem: str) -> list[str]:
    """Sub-names obtained by removing a leading or trailing segment."""
    parts = stem.split("-")
    variants: list[str] = []
    if len(parts) > 1:
        variants.append("-".join(parts[1:]))
        variants.append("-".join(parts[:-1]))
    return [v for v in variants if v]


@lru_cache(maxsize=16)
def load_reference_set(ecosystem: str, limit: int = 2000) -> ReferenceSet:
    """Load and index an ecosystem's reference set. Cached per process."""
    path = DATA_DIR / f"{ecosystem}.json"
    if not path.exists():
        logger.warning(
            "No reference set for %s at %s; typosquat detection will be skipped. "
            "Run scripts/refresh_reference_sets.py to build one.",
            ecosystem,
            path,
        )
        return ReferenceSet(ecosystem, [], source="missing")
    try:
        payload = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("Could not read reference set %s: %s", path, exc)
        return ReferenceSet(ecosystem, [], source="unreadable")
    names = list(payload.get("packages") or [])[:limit]
    return ReferenceSet(ecosystem, names, source=payload.get("source", ""))


def available_reference_sets() -> dict[str, int]:
    """Ecosystem -> reference set size, for the API's capability endpoint."""
    if not DATA_DIR.exists():
        return {}
    sizes: dict[str, int] = {}
    for path in sorted(DATA_DIR.glob("*.json")):
        try:
            sizes[path.stem] = int(json.loads(path.read_text()).get("count", 0))
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            continue
    return sizes
