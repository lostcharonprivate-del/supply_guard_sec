"""Project risk scoring.

A finding list is not a risk assessment. Two projects can each have "12
vulnerabilities" while one of them has a critical remote-code-execution flaw in
a direct production dependency and the other has twelve low-severity issues six
levels deep in a dev-only tree.

The model multiplies four factors that are each independently defensible:

    severity  x  exploitability  x  depth  x  confidence

* **Severity** comes from the CVSS base score where one exists.
* **Exploitability** is derived from the CVSS *vector* — network-reachable,
  no privileges, no user interaction is what actually gets exploited — rather
  than being an invented number.
* **Depth** discounts transitive packages, because a direct dependency is both
  more likely to be reached and immediately actionable.
* **Confidence** discounts heuristic findings so that a probable typosquat
  never outweighs a confirmed CVE.

The per-finding risks are then combined through a saturating curve, so that
volume matters but a project cannot be pushed to 100 by a long tail of
low-severity noise.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from supplyguard.core.types import Finding, FindingCategory, Severity

#: How much each finding category matters relative to a CVE of equal severity.
CATEGORY_WEIGHTS: dict[FindingCategory, float] = {
    # A confirmed malicious package is already executing attacker code; it is
    # strictly worse than a vulnerability of the same nominal severity.
    FindingCategory.MALICIOUS: 1.6,
    FindingCategory.DEPENDENCY_CONFUSION: 1.3,
    FindingCategory.TYPOSQUAT: 1.3,
    FindingCategory.VULNERABILITY: 1.0,
    FindingCategory.CI_ANOMALY: 1.0,
    # Staleness is a leading indicator, not a live exposure. Weighted low
    # enough that a neglected-but-uncompromised project is not mistaken for a
    # breached one.
    FindingCategory.STALE: 0.15,
}

#: Dev-only dependencies do not ship to production. They still matter — a
#: compromised build tool runs on developer machines and CI — so the discount
#: is partial rather than an exclusion.
DEV_DEPENDENCY_FACTOR = 0.45

#: Controls how fast depth discounts risk. At 0.35, depth 1 keeps 74% of the
#: weight and depth 5 keeps 36%.
DEPTH_DECAY = 0.35

#: Total exposure at which the score reaches ~63/100. Calibrated so that a
#: single critical, directly-reachable vulnerability lands around 45.
EXPOSURE_SCALE = 25.0

#: A confirmed-malicious dependency is not a point on a curve — attacker code
#: is already in the tree and has already executed at install time. Any such
#: finding floors the project score in the failing band regardless of what else
#: the arithmetic produces.
CONFIRMED_MALICIOUS_FLOOR = 75.0

GRADE_BANDS: list[tuple[float, str]] = [
    (10.0, "A"),
    (25.0, "B"),
    (45.0, "C"),
    (70.0, "D"),
    (100.1, "F"),
]


@dataclass(slots=True)
class Contribution:
    """One finding's contribution to the project score."""

    finding_key: str
    package: str | None
    category: FindingCategory
    severity: Severity
    risk: float
    severity_weight: float
    exploitability: float
    depth_factor: float
    confidence: float
    category_weight: float
    dev_factor: float

    def explain(self) -> str:
        return (
            f"{self.severity_weight:.1f} (severity) x {self.exploitability:.2f} "
            f"(exploitability) x {self.depth_factor:.2f} (depth) x "
            f"{self.confidence:.2f} (confidence) x {self.category_weight:.2f} "
            f"(category)"
            + (f" x {self.dev_factor:.2f} (dev-only)" if self.dev_factor < 1.0 else "")
            + f" = {self.risk:.2f}"
        )


@dataclass(slots=True)
class RiskScore:
    """A project's aggregate risk, with the arithmetic kept inspectable."""

    score: float
    grade: str
    exposure: float
    total_findings: int
    #: Set when a floor rule overrode the computed score, with the reason.
    floor_reason: str | None = None
    by_severity: dict[str, int] = field(default_factory=dict)
    by_category: dict[str, int] = field(default_factory=dict)
    category_exposure: dict[str, float] = field(default_factory=dict)
    top_contributors: list[Contribution] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "score": self.score,
            "grade": self.grade,
            "exposure": round(self.exposure, 2),
            "total_findings": self.total_findings,
            "floor_reason": self.floor_reason,
            "by_severity": self.by_severity,
            "by_category": self.by_category,
            "category_exposure": {
                k: round(v, 2) for k, v in self.category_exposure.items()
            },
            "top_contributors": [
                {
                    "package": c.package,
                    "category": c.category.value,
                    "severity": c.severity.value,
                    "risk": round(c.risk, 2),
                    "explanation": c.explain(),
                }
                for c in self.top_contributors
            ],
        }


def depth_factor(depth: int, is_direct: bool) -> float:
    """Weight a finding by how far the package sits from the project root."""
    if is_direct or depth <= 0:
        return 1.0
    # Packages the parser could not place (depth 99) are treated as deep but
    # not zero — they are still installed.
    effective = min(depth, 10)
    return round(1.0 / (1.0 + DEPTH_DECAY * effective), 4)


def finding_risk(finding: Finding) -> Contribution:
    """Compute one finding's contribution."""
    severity_weight = finding.severity.weight
    exploitability = float(finding.metadata.get("exploitability") or 1.0)
    # Keep the exploitability multiplier inside the range the CVSS helper
    # produces, so bad metadata cannot inflate a score.
    exploitability = max(0.5, min(1.5, exploitability))
    factor = depth_factor(finding.depth, finding.is_direct)
    confidence = max(0.0, min(1.0, finding.confidence))
    category_weight = CATEGORY_WEIGHTS.get(finding.category, 1.0)
    dev_factor = DEV_DEPENDENCY_FACTOR if finding.metadata.get("is_dev") else 1.0

    risk = (
        severity_weight
        * exploitability
        * factor
        * confidence
        * category_weight
        * dev_factor
    )
    return Contribution(
        finding_key=finding.dedupe_key,
        package=(
            f"{finding.package_name}@{finding.package_version}"
            if finding.package_name
            else None
        ),
        category=finding.category,
        severity=finding.severity,
        risk=risk,
        severity_weight=severity_weight,
        exploitability=exploitability,
        depth_factor=factor,
        confidence=confidence,
        category_weight=category_weight,
        dev_factor=dev_factor,
    )


def score_findings(findings: list[Finding]) -> RiskScore:
    """Aggregate findings into a 0-100 project risk score (higher is worse)."""
    contributions = [finding_risk(f) for f in findings]
    exposure = sum(c.risk for c in contributions)

    # Saturating curve: additional findings always raise the score, but with
    # diminishing effect, so a project cannot be pinned at 100 by volume alone.
    score = 100.0 * (1.0 - math.exp(-exposure / EXPOSURE_SCALE)) if exposure > 0 else 0.0

    floor_reason: str | None = None
    confirmed_malicious = [
        f
        for f in findings
        if f.category is FindingCategory.MALICIOUS and f.confidence >= 0.99
    ]
    if confirmed_malicious and score < CONFIRMED_MALICIOUS_FLOOR:
        names = ", ".join(
            sorted({f.package_name or "unknown" for f in confirmed_malicious})[:3]
        )
        score = CONFIRMED_MALICIOUS_FLOOR
        floor_reason = (
            f"Score floored at {CONFIRMED_MALICIOUS_FLOOR:.0f}: "
            f"{len(confirmed_malicious)} confirmed-malicious package(s) present "
            f"({names}). Malicious code in the dependency tree has already run at "
            "install time; this is an incident, not a backlog item."
        )
    score = round(score, 1)

    by_severity: dict[str, int] = {}
    by_category: dict[str, int] = {}
    category_exposure: dict[str, float] = {}
    for contribution in contributions:
        by_severity[contribution.severity.value] = (
            by_severity.get(contribution.severity.value, 0) + 1
        )
        by_category[contribution.category.value] = (
            by_category.get(contribution.category.value, 0) + 1
        )
        category_exposure[contribution.category.value] = (
            category_exposure.get(contribution.category.value, 0.0) + contribution.risk
        )

    return RiskScore(
        score=score,
        grade=grade_for(score),
        exposure=exposure,
        total_findings=len(findings),
        by_severity=by_severity,
        by_category=by_category,
        category_exposure=category_exposure,
        floor_reason=floor_reason,
        top_contributors=sorted(contributions, key=lambda c: -c.risk)[:10],
    )


def grade_for(score: float) -> str:
    for threshold, grade in GRADE_BANDS:
        if score < threshold:
            return grade
    return "F"
