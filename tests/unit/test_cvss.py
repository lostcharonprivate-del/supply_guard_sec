"""CVSS base-score computation.

Expected values are the published scores for these vectors; several are taken
from well-known advisories so that a regression is obvious.
"""

from __future__ import annotations

import pytest

from supplyguard.core.cvss import parse_vector, score_from_vector


@pytest.mark.parametrize(
    ("vector", "expected"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),   # unauthenticated RCE
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),   # remote DoS
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),   # reflected XSS
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),
        ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
        ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L", 3.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", 5.3),   # lodash ReDoS
        ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H", 7.4),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),   # no impact
    ],
)
def test_base_score_matches_published_values(vector: str, expected: float) -> None:
    score, _ = score_from_vector(vector)
    assert score == expected


def test_scope_change_applies_the_multiplier() -> None:
    unchanged, _ = score_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L")
    changed, _ = score_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L")
    assert changed > unchanged


def test_exploitability_ranks_remote_unauthenticated_highest() -> None:
    remote, remote_factor = score_from_vector(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    )
    local, local_factor = score_from_vector(
        "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:H"
    )
    assert remote_factor > local_factor
    assert 0.5 <= local_factor <= 1.5 and 0.5 <= remote_factor <= 1.5
    assert remote is not None and local is not None


@pytest.mark.parametrize("value", [None, "", "not-a-vector", "CVSS:9.9/XX:Y"])
def test_malformed_vectors_do_not_raise(value: str | None) -> None:
    score, factor = score_from_vector(value)
    assert score is None
    assert factor == 1.0


def test_v4_vectors_parse_but_are_not_scored_locally() -> None:
    # v4.0 scoring needs the official lookup tables; the advisory's own label
    # is used instead, so the vector must parse without producing a wrong score.
    parsed = parse_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H")
    assert parsed is not None
    assert parsed.version == "4.0"
    assert parsed.base_score() is None
