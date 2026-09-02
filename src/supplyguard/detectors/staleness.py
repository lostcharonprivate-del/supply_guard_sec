"""Staleness detection: unmaintained dependencies as a leading risk signal.

A package that has not shipped in years, or that the project is several major
versions behind on, is not a vulnerability today. It is a *predictor*: it is
where the next unpatchable CVE lands, and it is the profile attackers look for
when hunting for an abandoned package whose maintainer will accept help.
"""

from __future__ import annotations

from typing import ClassVar

from supplyguard.core.types import Evidence, Finding, FindingCategory, Severity
from supplyguard.detectors.base import Detector, ScanContext, register_detector
from supplyguard.utils.dates import days_since


@register_detector
class StalenessDetector(Detector):
    name: ClassVar[str] = "staleness"
    category: ClassVar[FindingCategory] = FindingCategory.STALE
    description: ClassVar[str] = (
        "Flags dependencies that are far behind the latest release or whose "
        "upstream project has gone quiet, even when no CVE is known."
    )
    known_false_positives: ClassVar[tuple[str, ...]] = (
        "Small, complete libraries legitimately stop changing. `leftpad`-shaped "
        "packages are 'stale' forever and that is fine.",
        "A deliberate major-version pin (to avoid a breaking change) looks "
        "identical to neglect from the registry's point of view.",
    )
    known_false_negatives: ClassVar[tuple[str, ...]] = (
        "A package receiving cosmetic releases looks maintained even when the "
        "security posture is not.",
        "Only the installed vs latest version is compared; a fork that has "
        "silently become the real upstream is not detected.",
    )

    async def detect(self, ctx: ScanContext) -> list[Finding]:
        config = ctx.config
        # Only direct dependencies are worth reporting: staleness is advisory,
        # and a deep transitive package is not something the user can act on.
        candidates = [
            p
            for p in ctx.packages
            if p.is_direct and p.version and not p.raw.get("unresolved")
        ]
        metadata = await ctx.metadata.get_many([p.name for p in candidates])

        findings: list[Finding] = []
        for package in candidates:
            meta = metadata.get(ctx.adapter.normalize_name(package.name))
            if meta is None or not meta.exists or not meta.latest_version:
                continue

            try:
                behind = ctx.adapter.compare_versions(meta.latest_version, package.version)
            except Exception:
                continue
            if behind <= 0:
                continue

            installed_release = meta.published_at(package.version)
            age_days = days_since(installed_release)
            latest_age_days = days_since(meta.last_published)
            majors = _majors_behind(ctx, package.version, meta.latest_version)

            evidence = [
                Evidence(
                    "Version gap",
                    f"installed {package.version}, latest {meta.latest_version}"
                    + (f" ({majors} major version(s) behind)" if majors else ""),
                )
            ]
            if age_days is not None:
                evidence.append(
                    Evidence(
                        "Installed release age", f"published {age_days / 365.25:.1f} years ago"
                    )
                )
            if latest_age_days is not None and latest_age_days > 365:
                evidence.append(
                    Evidence(
                        "Upstream activity",
                        f"the newest release upstream is itself "
                        f"{latest_age_days / 365.25:.1f} years old",
                    )
                )
            if meta.deprecated:
                evidence.append(Evidence("Deprecated", "The registry marks this package deprecated."))

            severity = Severity.INFO
            if meta.deprecated:
                severity = Severity.MEDIUM
            elif majors and majors >= 2 and (age_days or 0) > config.stale_days_behind or majors or (age_days or 0) > config.stale_days_behind:
                severity = Severity.LOW
            else:
                # Merely one patch behind is noise, not a finding.
                continue

            findings.append(
                Finding(
                    category=self.category,
                    severity=severity,
                    title=(
                        f"{package.name} is deprecated"
                        if meta.deprecated
                        else f"{package.name} is {majors or 'several'} version(s) behind"
                    ),
                    description=(
                        f"{package.name}@{package.version} is behind the current "
                        f"release {meta.latest_version}. Outdated dependencies are "
                        "where unpatched vulnerabilities accumulate and are a "
                        "common target for maintainer-takeover attacks."
                    ),
                    package_name=package.name,
                    package_version=package.version,
                    ecosystem=ctx.adapter.name,
                    identifier=f"STALE-{package.name}",
                    fixed_version=meta.latest_version,
                    remediation=(
                        f"Review the changelog and upgrade {package.name} to "
                        f"{meta.latest_version}."
                        if not meta.deprecated
                        else f"{package.name} is deprecated upstream; migrate to the "
                        "replacement named in its registry page."
                    ),
                    references=[ctx.adapter.registry_package_url(package.name)],
                    evidence=evidence,
                    confidence=0.9 if meta.deprecated else 0.6,
                    depth=package.depth,
                    is_direct=package.is_direct,
                    metadata={
                        "latest_version": meta.latest_version,
                        "majors_behind": majors,
                        "installed_age_days": age_days,
                    },
                )
            )
        return findings


def _majors_behind(ctx: ScanContext, installed: str, latest: str) -> int | None:
    """Major-version distance, when both versions expose a leading integer."""
    def major(value: str) -> int | None:
        head = value.strip().lstrip("v=").split(".", 1)[0]
        return int(head) if head.isdigit() else None

    a, b = major(installed), major(latest)
    if a is None or b is None or b <= a:
        return None
    return b - a
