"""Typosquatting detection.

A name that merely *looks* like a popular package is not evidence of an attack:
`preact` and `react` are one edit apart and both legitimate. What separates a
squat from a coincidence is the combination of

  1. a strong name-similarity signal against a genuinely popular package, and
  2. the candidate itself being obscure — few downloads, recently published, or
     not resolvable on the registry at all.

Both halves are required before anything is reported, and the detector always
explains which signals fired so a reviewer can dismiss a false positive fast.
"""

from __future__ import annotations

from typing import ClassVar

from supplyguard.core.types import (
    Evidence,
    Finding,
    FindingCategory,
    PackageMetadata,
    ResolvedPackage,
    Severity,
)
from supplyguard.detectors.base import Detector, ScanContext, register_detector
from supplyguard.detectors.reference_sets import ReferencePackage, ReferenceSet, load_reference_set
from supplyguard.detectors.similarity import Signal, SignalKind, analyse_pair
from supplyguard.utils.dates import days_since

#: Signals strong enough to justify a finding on their own when corroborated.
_STRONG_SIGNALS = {
    SignalKind.HOMOGLYPH,
    SignalKind.ASCII_LOOKALIKE,
    SignalKind.TRANSPOSITION,
    SignalKind.KEYBOARD_ADJACENT,
    SignalKind.SCOPE_CONFUSION,
    SignalKind.SPELLING_VARIANT,
    SignalKind.PLURALISATION,
    SignalKind.REPEATED_CHARACTER,
    SignalKind.DIGIT_VARIANT,
}


@register_detector
class TyposquatDetector(Detector):
    name: ClassVar[str] = "typosquat"
    category: ClassVar[FindingCategory] = FindingCategory.TYPOSQUAT
    description: ClassVar[str] = (
        "Compares every dependency against the most-downloaded packages in its "
        "ecosystem using edit distance, transposition, keyboard adjacency, "
        "homoglyph and structural-variant analysis, then corroborates with the "
        "candidate's own download count and age before reporting."
    )
    known_false_positives: ClassVar[tuple[str, ...]] = (
        "Legitimate ecosystem ports and companions genuinely resemble the "
        "package they complement (`django-redis` vs `redis`); the affix signal "
        "is deliberately weak for this reason.",
        "A new, low-download internal package whose name happens to sit near a "
        "popular one will be flagged until it accrues downloads.",
        "Download counts are unavailable for Maven Central, so corroboration "
        "there falls back to publication age alone and is weaker.",
    )
    known_false_negatives: ClassVar[tuple[str, ...]] = (
        "Only the top ~2,000 packages per ecosystem form the reference set, so "
        "a squat of a moderately popular package is missed.",
        "A squat whose name is not similar at all — a plausible-sounding "
        "invented name with no popular counterpart — is out of scope here; that "
        "is what the malicious-package heuristics are for.",
        "A squat that has already accumulated real downloads (through a "
        "long-running campaign) will fail the corroboration step.",
    )
    requires_network: ClassVar[bool] = False  # degrades gracefully without it

    async def detect(self, ctx: ScanContext) -> list[Finding]:
        reference = load_reference_set(
            ctx.adapter.name, limit=ctx.config.reference_set_size
        )
        if not len(reference):
            ctx.notes.append(
                f"No typosquat reference set available for {ctx.adapter.name}; "
                "detector skipped."
            )
            return []

        suspects: list[tuple[ResolvedPackage, ReferencePackage, list[Signal]]] = []
        for package in _unique_by_name(ctx.packages):
            match = self._best_match(ctx, reference, package)
            if match is not None:
                suspects.append((package, *match))

        if not suspects:
            return []

        # Only now spend registry calls, and only on the shortlist.
        names = [p.name for p, _, _ in suspects]
        metadata = await ctx.metadata.get_many(names)
        downloads = await self._download_counts(ctx, names)

        findings: list[Finding] = []
        for package, target, signals in suspects:
            key = ctx.adapter.normalize_name(package.name)
            meta = metadata.get(key)
            if meta is not None and meta.downloads_last_month is None:
                meta.downloads_last_month = downloads.get(key)
            finding = self._build_finding(ctx, package, target, signals, meta)
            if finding is not None:
                findings.append(finding)
        return findings

    async def _download_counts(self, ctx: ScanContext, names: list[str]) -> dict[str, int | None]:
        """Fetch download counts for the shortlist, when the registry has them."""
        if ctx.adapter.download_metric == "none":
            return {}
        results = await ctx.http.gather([ctx.metadata.downloads(n) for n in names])
        return {
            ctx.adapter.normalize_name(name): (value if isinstance(value, int) else None)
            for name, value in zip(names, results, strict=False)
        }

    # -- matching -----------------------------------------------------------
    def _best_match(
        self, ctx: ScanContext, reference: ReferenceSet, package: ResolvedPackage
    ) -> tuple[ReferencePackage, list[Signal]] | None:
        name = package.name
        if len(name) < ctx.config.typosquat_min_name_length:
            return None
        # The decisive guard: a package that is itself popular is not a squat.
        if reference.contains(name):
            return None

        best: tuple[ReferencePackage, list[Signal]] | None = None
        best_score = 0.0
        for target in reference.candidates(name, max_distance=ctx.config.max_edit_distance):
            signals = analyse_pair(
                name, target.name, max_distance=ctx.config.max_edit_distance
            )
            if not signals:
                continue
            score = _signal_score(signals) * (0.6 + 0.4 * target.popularity)
            if score > best_score:
                best_score, best = score, (target, signals)
        return best

    # -- reporting ----------------------------------------------------------
    def _build_finding(
        self,
        ctx: ScanContext,
        package: ResolvedPackage,
        target: ReferencePackage,
        signals: list[Signal],
        meta: PackageMetadata | None,
    ) -> Finding | None:
        config = ctx.config
        evidence = [
            Evidence(signal.kind.replace("_", " ").title(), signal.explanation, signal.strength)
            for signal in signals
        ]
        evidence.append(
            Evidence(
                "Imitation target",
                f"'{target.name}' is ranked #{target.rank + 1} by downloads in "
                f"{ctx.adapter.display_name}.",
            )
        )

        similarity = _signal_score(signals)
        corroboration = 0.0
        corroborated = False

        if meta is None or not meta.exists:
            # Cannot confirm; report at low confidence rather than dropping it.
            evidence.append(
                Evidence(
                    "Registry lookup",
                    "Could not retrieve registry metadata, so download count and "
                    "age could not be checked. Confidence is reduced accordingly.",
                )
            )
            corroboration = 0.15
        else:
            age_days = days_since(meta.first_published)
            # RubyGems only publishes lifetime totals; scale the threshold so a
            # gem is not judged obscure by a yardstick built for monthly figures.
            download_threshold = config.typosquat_max_downloads * (
                50 if ctx.adapter.download_metric == "lifetime" else 1
            )
            metric_label = (
                "downloads (lifetime)"
                if ctx.adapter.download_metric == "lifetime"
                else "downloads last month"
            )

            if age_days is not None and age_days <= config.typosquat_max_age_days:
                corroborated = True
                corroboration += 0.35
                evidence.append(
                    Evidence(
                        "Package age",
                        f"First published {age_days:.0f} days ago — new packages "
                        "resembling popular ones are the typosquat profile.",
                        0.35,
                    )
                )
            elif age_days is not None:
                evidence.append(
                    Evidence(
                        "Package age",
                        f"First published {age_days / 365.25:.1f} years ago, which "
                        "argues against an opportunistic squat.",
                    )
                )

            if meta.downloads_last_month is not None:
                if meta.downloads_last_month <= download_threshold:
                    corroborated = True
                    corroboration += 0.35
                    evidence.append(
                        Evidence(
                            "Downloads",
                            f"{meta.downloads_last_month:,} {metric_label} "
                            f"versus a target ranked #{target.rank + 1}.",
                            0.35,
                        )
                    )
                else:
                    # A widely-used package with a similar name is a real
                    # project, not a squat. Suppress unless the name is
                    # visually identical, which no legitimate project needs.
                    evidence.append(
                        Evidence(
                            "Downloads",
                            f"{meta.downloads_last_month:,} {metric_label} — "
                            "too widely used to be an opportunistic squat.",
                        )
                    )
                    if not any(s.kind is SignalKind.HOMOGLYPH for s in signals):
                        return None
            if not meta.repository_url:
                corroboration += 0.1
                evidence.append(
                    Evidence("Repository", "No source repository is linked.", 0.1)
                )

        # Require corroboration for anything but a visually identical name.
        # A name that renders identically to a popular package has no innocent
        # explanation, so it stands on its own.
        decisive = any(
            s.kind in (SignalKind.HOMOGLYPH, SignalKind.ASCII_LOOKALIKE) for s in signals
        )
        if not decisive and not corroborated and meta is not None and meta.exists:
            return None
        if not decisive and similarity < 0.6 and corroboration < 0.3:
            return None

        confidence = round(min(0.99, similarity * 0.7 + corroboration), 2)
        severity = _severity_for(confidence, decisive, package)

        return Finding(
            category=self.category,
            severity=severity,
            title=f"{package.name} closely resembles {target.name}",
            description=(
                f"'{package.name}' is name-similar to '{target.name}', one of the "
                f"most-downloaded packages in {ctx.adapter.display_name}, but is "
                "not that package. "
                + (
                    "The names are visually indistinguishable."
                    if decisive
                    else "Its own popularity and age are consistent with a squat."
                )
            ),
            package_name=package.name,
            package_version=package.version,
            ecosystem=ctx.adapter.name,
            identifier=f"TYPOSQUAT-{package.name}-{target.name}",
            remediation=(
                f"Confirm that '{package.name}' is the package you intended. If you "
                f"meant '{target.name}', remove '{package.name}', reinstall the "
                "correct package, and treat any machine that installed it as "
                "potentially compromised — install-time code has already run."
            ),
            references=[
                ctx.adapter.registry_package_url(package.name),
                ctx.adapter.registry_package_url(target.name),
            ],
            evidence=evidence,
            confidence=confidence,
            depth=package.depth,
            is_direct=package.is_direct,
            metadata={
                "imitation_target": target.name,
                "target_rank": target.rank + 1,
                "signals": [s.kind.value for s in signals],
                "similarity_score": round(similarity, 3),
            },
        )


def _unique_by_name(packages: list[ResolvedPackage]) -> list[ResolvedPackage]:
    """One entry per distinct name; a squat is a name problem, not a version one."""
    seen: dict[str, ResolvedPackage] = {}
    for package in packages:
        current = seen.get(package.name)
        if current is None or package.depth < current.depth:
            seen[package.name] = package
    return list(seen.values())


def _signal_score(signals: list[Signal]) -> float:
    """Combine signals, rewarding independent corroboration with diminishing returns."""
    if not signals:
        return 0.0
    ordered = sorted(signals, key=lambda s: -s.strength)
    score = ordered[0].strength
    for extra in ordered[1:]:
        score += extra.strength * (1.0 - score) * 0.5
    if any(s.kind in _STRONG_SIGNALS for s in signals):
        score = min(1.0, score + 0.05)
    return min(1.0, score)


def _severity_for(confidence: float, decisive: bool, package: ResolvedPackage) -> Severity:
    if decisive or confidence >= 0.85:
        return Severity.CRITICAL if package.is_direct else Severity.HIGH
    if confidence >= 0.7:
        return Severity.HIGH
    if confidence >= 0.5:
        return Severity.MEDIUM
    return Severity.LOW
