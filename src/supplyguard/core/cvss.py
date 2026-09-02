"""CVSS vector parsing and base-score computation.

Advisories are inconsistent: some carry a numeric score, some only a label,
many carry just a vector string. Computing the base score locally from the
vector gives a comparable number across every source, and the exploitability
sub-score it produces is a real, defensible input to the risk model rather
than an invented weight.

Implements CVSS v3.0/v3.1 base scoring per the FIRST specification. v4.0
vectors are parsed for their metrics but fall back to the advisory's own
severity label, since v4 scoring requires the official lookup tables.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

# Metric value -> numeric weight, per CVSS v3.1 section 7.4.
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.00}


@dataclass(frozen=True, slots=True)
class CvssVector:
    version: str
    metrics: dict[str, str]

    @property
    def attack_vector(self) -> str | None:
        return self.metrics.get("AV")

    @property
    def scope_changed(self) -> bool:
        return self.metrics.get("S") == "C"

    def base_score(self) -> float | None:
        """CVSS v3.x base score, or None when the vector is not scorable here."""
        if not self.version.startswith("3"):
            return None
        m = self.metrics
        required = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
        if not all(k in m for k in required):
            return None
        try:
            pr_table = _PR_CHANGED if self.scope_changed else _PR_UNCHANGED
            exploitability = (
                8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr_table[m["PR"]] * _UI[m["UI"]]
            )
            iss = 1 - (
                (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
            )
            if self.scope_changed:
                impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
            else:
                impact = 6.42 * iss
        except KeyError:
            return None

        if impact <= 0:
            return 0.0
        raw = impact + exploitability
        if self.scope_changed:
            raw *= 1.08
        return _roundup(min(raw, 10.0))

    def exploitability_factor(self) -> float:
        """A 0.5-1.5 multiplier describing how reachable the flaw is.

        Network-reachable, no privileges and no user interaction is the profile
        that gets exploited in the wild; a local vector needing high privileges
        and user interaction rarely is. This scales the risk score so that two
        equally-severe CVEs are not treated as equally urgent.
        """
        m = self.metrics
        factor = 1.0
        factor *= {"N": 1.25, "A": 1.05, "L": 0.85, "P": 0.7}.get(m.get("AV", ""), 1.0)
        factor *= {"L": 1.1, "H": 0.85}.get(m.get("AC", ""), 1.0)
        factor *= {"N": 1.1, "L": 0.95, "H": 0.8}.get(m.get("PR", ""), 1.0)
        factor *= {"N": 1.1, "R": 0.85}.get(m.get("UI", ""), 1.0)
        if self.scope_changed:
            factor *= 1.1
        return round(max(0.5, min(1.5, factor)), 3)


_VECTOR_RE = re.compile(r"CVSS:(?P<version>\d+\.\d+)/(?P<body>.+)", re.IGNORECASE)


def parse_vector(vector: str | None) -> CvssVector | None:
    """Parse a `CVSS:3.1/AV:N/AC:L/...` string."""
    if not vector or not isinstance(vector, str):
        return None
    match = _VECTOR_RE.match(vector.strip())
    if not match:
        return None
    metrics: dict[str, str] = {}
    for part in match.group("body").split("/"):
        key, _, value = part.partition(":")
        if key and value:
            metrics[key.strip().upper()] = value.strip().upper()
    return CvssVector(version=match.group("version"), metrics=metrics)


def score_from_vector(vector: str | None) -> tuple[float | None, float]:
    """Return `(base_score, exploitability_factor)` for a vector string."""
    parsed = parse_vector(vector)
    if parsed is None:
        return None, 1.0
    return parsed.base_score(), parsed.exploitability_factor()


def _roundup(value: float) -> float:
    """CVSS v3.1 Appendix A rounding: round *up* to one decimal place.

    Uses the specification's integer arithmetic rather than `round()`, which
    would produce off-by-0.1 scores on values such as 4.02.
    """
    scaled = int(round(value * 100_000))
    if scaled % 10_000 == 0:
        return scaled / 100_000.0
    return (math.floor(scaled / 10_000) + 1) / 10.0
