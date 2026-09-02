"""Malicious package detection.

Two layers, deliberately:

1. **Known-bad intelligence.** OSV.dev republishes the `ossf/malicious-packages`
   dataset under `MAL-` identifiers. That is a curated, human-reviewed feed of
   packages confirmed malicious, and it costs one query that the vulnerability
   detector has already made and cached. Nothing heuristic competes with a
   confirmed hit, so it is reported at critical severity on its own.

2. **Heuristics**, for packages nobody has reported yet. Each is individually
   weak — plenty of legitimate packages lack a README — so they are scored
   together and only reported once enough independent signals agree. The one
   exception is install-script analysis: a `postinstall` that pipes a download
   into a shell needs no corroboration.
"""

from __future__ import annotations

from datetime import datetime
from typing import ClassVar

from supplyguard.clients.osv import OSVClient, Vulnerability
from supplyguard.core.types import (
    Evidence,
    Finding,
    FindingCategory,
    PackageMetadata,
    PackageRef,
    ResolvedPackage,
    Severity,
)
from supplyguard.detectors.base import Detector, ScanContext, register_detector
from supplyguard.detectors.script_analysis import (
    ScriptAnalysis,
    analyse_scripts,
    combined_score,
)
from supplyguard.utils.dates import days_since

#: Heuristic score at which a package is worth a human's attention.
_REPORT_THRESHOLD = 0.55


@register_detector
class MaliciousPackageDetector(Detector):
    name: ClassVar[str] = "malicious"
    category: ClassVar[FindingCategory] = FindingCategory.MALICIOUS
    description: ClassVar[str] = (
        "Cross-references the OSV malicious-package feed (sourced from "
        "ossf/malicious-packages), then applies metadata and install-script "
        "heuristics to packages nobody has reported yet."
    )
    known_false_positives: ClassVar[tuple[str, ...]] = (
        "New, small or internal packages legitimately have few downloads, no "
        "README and no linked repository. Several signals must agree before "
        "anything is reported, but a genuinely obscure package can still trip "
        "the threshold.",
        "Native modules must run code at install time; `node-gyp rebuild` and "
        "similar are allowlisted, but unusual build wrappers are not.",
        "A long-dormant package receiving a legitimate revival release matches "
        "the maintainer-takeover profile exactly.",
    )
    known_false_negatives: ClassVar[tuple[str, ...]] = (
        "Only metadata and registry-exposed scripts are analysed — package "
        "*contents* are never downloaded or unpacked. Malicious code in the "
        "library body rather than an install hook is invisible here.",
        "A patient attacker who builds a plausible README, links a real "
        "repository and waits out the age threshold defeats every heuristic.",
        "The MAL- feed only covers packages that have already been reported and "
        "reviewed, which is always after the fact.",
    )

    async def detect(self, ctx: ScanContext) -> list[Finding]:
        findings = await self._known_malicious(ctx)
        reported = {f.package_name for f in findings}
        findings.extend(await self._heuristic(ctx, skip=reported))
        return findings

    # -- layer 1: confirmed malicious ---------------------------------------
    async def _known_malicious(self, ctx: ScanContext) -> list[Finding]:
        packages = [p for p in ctx.packages if p.version and not p.raw.get("unresolved")]
        if not packages:
            return []
        # The vulnerability detector issues the same query; the HTTP cache
        # serves this one, so the second pass costs no extra round-trips.
        client = OSVClient(ctx.http)
        refs = [PackageRef(ctx.adapter.osv_ecosystem, p.name, p.version) for p in packages]
        results = await client.scan(refs)
        by_key = {
            PackageRef(ctx.adapter.osv_ecosystem, p.name, p.version).key: p for p in packages
        }

        findings: list[Finding] = []
        for key, vulns in results.items():
            package = by_key.get(key)
            if package is None:
                continue
            for vuln in vulns:
                if vuln.is_malicious:
                    findings.append(self._malicious_finding(ctx, package, vuln))
        return findings

    def _malicious_finding(
        self, ctx: ScanContext, package: ResolvedPackage, vuln: Vulnerability
    ) -> Finding:
        return Finding(
            category=self.category,
            severity=Severity.CRITICAL,
            title=f"{package.name}@{package.version} is a known-malicious package",
            description=(
                (vuln.summary or vuln.details[:400] or "")
                + f"\n\nThis release is recorded as malicious by {vuln.malicious_source}. "
                "It has been reviewed and confirmed to contain attacker-planted "
                "code — this is not a heuristic assessment."
            ).strip(),
            package_name=package.name,
            package_version=package.version,
            ecosystem=ctx.adapter.name,
            identifier=vuln.id,
            affected_range=vuln.affected_range,
            remediation=(
                f"Remove {package.name} immediately. Treat every machine and CI "
                "runner that installed it as compromised: install-time code has "
                "already executed with the installing user's privileges. Rotate "
                "any credential that was present in those environments — "
                "registry tokens, cloud keys, SSH keys — and audit for "
                "persistence before restoring service."
            ),
            references=vuln.references,
            evidence=[
                Evidence(
                    "Confirmed malicious",
                    f"Recorded as {vuln.id} by {vuln.malicious_source}.",
                    1.0,
                ),
                Evidence(
                    "Affected versions",
                    vuln.affected_range or "all published versions",
                    0.8,
                ),
                Evidence(
                    "Position in tree",
                    "Direct dependency"
                    if package.is_direct
                    else f"Transitive dependency at depth {package.depth}, reached via "
                    + (", ".join(package.parents[:3]) or "an unrecorded path"),
                ),
            ],
            confidence=1.0,
            depth=package.depth,
            is_direct=package.is_direct,
            metadata={"osv_id": vuln.id, "source": "ossf/malicious-packages"},
        )

    # -- layer 2: heuristics -------------------------------------------------
    async def _heuristic(self, ctx: ScanContext, skip: set[str | None]) -> list[Finding]:
        candidates = _unique_by_name(
            [
                p
                for p in ctx.packages
                if p.name not in skip
                and p.depth <= ctx.config.metadata_max_depth
                and not p.raw.get("unresolved")
            ]
        )
        if not candidates:
            return []

        metadata = await ctx.metadata.get_many([p.name for p in candidates])
        if ctx.metadata.budget_exhausted:
            ctx.notes.append(
                "Registry metadata budget was exhausted; malicious-package "
                "heuristics ran on a subset of the dependency tree."
            )

        findings: list[Finding] = []
        for package in candidates:
            meta = metadata.get(ctx.adapter.normalize_name(package.name))
            finding = self._assess(ctx, package, meta)
            if finding is not None:
                findings.append(finding)
        return findings

    def _assess(
        self, ctx: ScanContext, package: ResolvedPackage, meta: PackageMetadata | None
    ) -> Finding | None:
        config = ctx.config
        evidence: list[Evidence] = []
        score = 0.0

        # --- install-time execution (stands alone) --------------------------
        scripts = dict(meta.install_scripts) if meta else {}
        scripts.update(package.raw.get("install_scripts") or {})
        analyses = analyse_scripts(scripts)
        script_score = combined_score(analyses) if analyses else 0.0
        for hook, analysis in analyses.items():
            for detection in analysis.detections:
                evidence.append(
                    Evidence(
                        f"Install hook '{hook}'",
                        f"{detection.description}."
                        + (f" Excerpt: `{detection.excerpt}`" if detection.excerpt else ""),
                        detection.weight,
                    )
                )
        if scripts and not analyses:
            evidence.append(
                Evidence(
                    "Install hooks",
                    f"Runs {', '.join(sorted(scripts))} at install time, but the "
                    "script bodies show no suspicious behaviour.",
                )
            )
        score = _combine(score, script_score)

        if meta is None or not meta.exists:
            # A package in the lockfile that the registry no longer serves is a
            # strong signal in itself: malicious packages get taken down.
            if package.version:
                evidence.append(
                    Evidence(
                        "Registry status",
                        "This package is in your lockfile but is no longer "
                        "published. Removal is what happens to packages found "
                        "to be malicious — and also to ones simply unpublished.",
                        0.45,
                    )
                )
                score = _combine(score, 0.45)
            if score < _REPORT_THRESHOLD:
                return None
            return self._build(ctx, package, evidence, score, meta)

        # --- age and popularity ---------------------------------------------
        age_days = days_since(meta.first_published)
        version_age_days = days_since(meta.published_at(package.version or ""))
        downloads = meta.downloads_last_month

        if age_days is not None and age_days <= config.new_package_age_days:
            weight = 0.4 if age_days <= 14 else 0.25
            evidence.append(
                Evidence(
                    "Recently published",
                    f"The package first appeared {age_days:.0f} days ago.",
                    weight,
                )
            )
            score = _combine(score, weight)

        if downloads is not None:
            # RubyGems reports lifetime totals, so the "obscure" threshold has
            # to be scaled or every gem looks popular.
            scale = 50 if ctx.adapter.download_metric == "lifetime" else 1
            if downloads <= config.low_download_threshold * scale:
                evidence.append(
                    Evidence(
                        "Very low adoption",
                        f"{downloads:,} downloads "
                        + ("(lifetime)" if scale > 1 else "last month")
                        + " — almost nobody is using this.",
                        0.25,
                    )
                )
                score = _combine(score, 0.25)

        # --- provenance ------------------------------------------------------
        if not meta.repository_url:
            evidence.append(
                Evidence(
                    "No source repository",
                    "The package links no source repository, so its published "
                    "artifact cannot be compared against reviewable source.",
                    0.2,
                )
            )
            score = _combine(score, 0.2)
        elif (mismatch := _repository_mismatch(package.name, meta.repository_url)) is not None:
            evidence.append(
                Evidence(
                    "Repository name mismatch",
                    mismatch,
                    0.35,
                )
            )
            score = _combine(score, 0.35)

        if not meta.has_readme or meta.readme_length < config.short_readme_length:
            evidence.append(
                Evidence(
                    "Missing or minimal README",
                    f"README is {meta.readme_length} characters. Packages built to "
                    "be installed by mistake rarely bother documenting themselves.",
                    0.15,
                )
            )
            score = _combine(score, 0.15)

        # --- maintainer takeover profile ------------------------------------
        if (dormancy := _dormancy_break(meta)) is not None:
            gap_years, release_age = dormancy
            if release_age <= config.maintainer_change_window_days:
                evidence.append(
                    Evidence(
                        "Release after long dormancy",
                        f"No releases for {gap_years:.1f} years, then a new release "
                        f"{release_age:.0f} days ago. Both the `event-stream` and "
                        "`ua-parser-js` compromises followed a handover of a "
                        "long-stable package.",
                        0.4,
                    )
                )
                score = _combine(score, 0.4)

        if meta.yanked:
            evidence.append(
                Evidence("Yanked", "The maintainer has yanked this release.", 0.3)
            )
            score = _combine(score, 0.3)

        # A brand-new version of an otherwise-established package, pulled in as
        # a direct dependency, is the shape of a compromised release.
        if (
            version_age_days is not None
            and version_age_days <= 7
            and age_days is not None
            and age_days > 365
            and script_score > 0
        ):
            evidence.append(
                Evidence(
                    "Very recent release with install hooks",
                    f"This exact version was published {version_age_days:.0f} days "
                    "ago on a long-established package, and it runs install-time code.",
                    0.35,
                )
            )
            score = _combine(score, 0.35)

        if score < _REPORT_THRESHOLD:
            return None
        return self._build(ctx, package, evidence, score, meta)

    def _build(
        self,
        ctx: ScanContext,
        package: ResolvedPackage,
        evidence: list[Evidence],
        score: float,
        meta: PackageMetadata | None,
    ) -> Finding:
        severity = (
            Severity.HIGH
            if score >= 0.8
            else Severity.MEDIUM
            if score >= 0.65
            else Severity.LOW
        )
        top = sorted(evidence, key=lambda e: -e.weight)[:2]
        return Finding(
            category=self.category,
            severity=severity,
            title=f"{package.name}@{package.version} shows suspicious characteristics",
            description=(
                f"'{package.name}' matched {len(evidence)} heuristic signal(s) "
                "associated with malicious packages: "
                + "; ".join(e.label.lower() for e in top)
                + ". This is a heuristic assessment, not a confirmed detection — "
                "review the evidence below before acting."
            ),
            package_name=package.name,
            package_version=package.version,
            ecosystem=ctx.adapter.name,
            identifier=f"MALHEUR-{package.name}",
            remediation=(
                f"Review {package.name} manually: read its published source, "
                "confirm the linked repository matches the artifact, and check "
                "who maintains it. If it runs install hooks, inspect them before "
                "the next `install` on any developer machine or CI runner."
            ),
            references=[ctx.adapter.registry_package_url(package.name)]
            + ([meta.repository_url] if meta and meta.repository_url else []),
            evidence=evidence,
            confidence=round(score, 2),
            depth=package.depth,
            is_direct=package.is_direct,
            metadata={
                "heuristic_score": round(score, 3),
                "signals": [e.label for e in evidence],
            },
        )


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _combine(current: float, addition: float) -> float:
    """Saturating combination: independent weak signals accumulate, never exceed 1."""
    return current + addition * (1.0 - current)


def _unique_by_name(packages: list[ResolvedPackage]) -> list[ResolvedPackage]:
    seen: dict[str, ResolvedPackage] = {}
    for package in packages:
        current = seen.get(package.name)
        if current is None or package.depth < current.depth:
            seen[package.name] = package
    return list(seen.values())


def _repository_mismatch(package_name: str, repository_url: str) -> str | None:
    """Whether a linked repository plausibly belongs to this package.

    A mismatch is weak on its own — monorepos legitimately host packages under
    unrelated names — so this only fires when the names share nothing at all.
    """
    from supplyguard.detectors.similarity import normalise_separators

    slug = repository_url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
    if not slug:
        return None
    normalised_slug = normalise_separators(slug)
    normalised_name = normalise_separators(package_name.lstrip("@").replace("/", "-"))
    bare_name = normalised_name.split("-")[-1]

    if (
        normalised_slug in normalised_name
        or normalised_name in normalised_slug
        or bare_name in normalised_slug
        or normalised_slug in bare_name
    ):
        return None
    # Share any meaningful token? Monorepos usually do.
    slug_tokens = {t for t in normalised_slug.split("-") if len(t) > 2}
    name_tokens = {t for t in normalised_name.split("-") if len(t) > 2}
    if slug_tokens & name_tokens:
        return None
    return (
        f"The package is named '{package_name}' but links to a repository named "
        f"'{slug}'. Verify the repository really produces this package."
    )


def _dormancy_break(meta: PackageMetadata) -> tuple[float, float] | None:
    """Detect a long publishing gap followed by a fresh release.

    Returns `(gap_in_years, days_since_newest_release)`, or None.
    """
    stamps: list[datetime] = sorted(v for v in meta.version_published.values() if v)
    if len(stamps) < 3:
        return None
    newest, previous = stamps[-1], stamps[-2]
    gap_days = (newest - previous).total_seconds() / 86_400.0
    if gap_days < 730:  # under two years is ordinary maintenance cadence
        return None
    release_age = days_since(newest)
    if release_age is None:
        return None
    return gap_days / 365.25, release_age
