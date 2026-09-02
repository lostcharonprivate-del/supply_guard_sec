"""Staleness detection."""

from __future__ import annotations

from datetime import timedelta

from supplyguard.core.types import PackageMetadata, ResolvedPackage, Severity
from supplyguard.detectors.staleness import StalenessDetector
from supplyguard.utils.dates import utcnow
from tests.conftest import make_context


def meta(name: str, latest: str, *, installed: str, installed_age: float, deprecated: bool = False):
    now = utcnow()
    return PackageMetadata(
        ecosystem="npm",
        name=name,
        latest_version=latest,
        version_published={
            installed: now - timedelta(days=installed_age),
            latest: now - timedelta(days=10),
        },
        last_published=now - timedelta(days=10),
        deprecated=deprecated,
    )


async def test_major_versions_behind_is_reported() -> None:
    ctx = make_context(
        "npm",
        [("old-lib", "1.0.0")],
        metadata={"old-lib": meta("old-lib", "4.0.0", installed="1.0.0", installed_age=1500)},
    )
    findings = await StalenessDetector().detect(ctx)
    assert len(findings) == 1
    assert findings[0].fixed_version == "4.0.0"
    assert findings[0].metadata["majors_behind"] == 3


async def test_a_single_patch_behind_is_not_a_finding() -> None:
    """Otherwise every scan reports every dependency, and the signal is lost."""
    ctx = make_context(
        "npm",
        [("lib", "1.0.0")],
        metadata={"lib": meta("lib", "1.0.1", installed="1.0.0", installed_age=30)},
    )
    assert await StalenessDetector().detect(ctx) == []


async def test_up_to_date_package_is_silent() -> None:
    ctx = make_context(
        "npm",
        [("lib", "2.0.0")],
        metadata={"lib": meta("lib", "2.0.0", installed="2.0.0", installed_age=5)},
    )
    assert await StalenessDetector().detect(ctx) == []


async def test_deprecated_packages_are_raised_to_medium() -> None:
    ctx = make_context(
        "npm",
        [("dead-lib", "1.0.0")],
        metadata={
            "dead-lib": meta(
                "dead-lib", "1.0.1", installed="1.0.0", installed_age=100, deprecated=True
            )
        },
    )
    findings = await StalenessDetector().detect(ctx)
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM


async def test_transitive_packages_are_not_reported() -> None:
    """Staleness is advisory, and a deep transitive package is not actionable."""
    ctx = make_context(
        "npm",
        [
            ResolvedPackage(
                ecosystem="npm", name="deep-lib", version="1.0.0", depth=3, is_direct=False
            )
        ],
        metadata={
            "deep-lib": meta("deep-lib", "5.0.0", installed="1.0.0", installed_age=2000)
        },
    )
    assert await StalenessDetector().detect(ctx) == []


async def test_missing_metadata_is_skipped_silently() -> None:
    ctx = make_context("npm", [("unknown-lib", "1.0.0")], metadata={})
    assert await StalenessDetector().detect(ctx) == []
