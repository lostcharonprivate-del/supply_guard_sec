"""Version ordering, per ecosystem.

These are the comparisons that decide whether SupplyGuard tells a user to
upgrade or (catastrophically) to downgrade, so the awkward cases are pinned.
"""

from __future__ import annotations

import pytest

from supplyguard.ecosystems.versions import (
    parse_gem_version,
    parse_maven_version,
    parse_pep440,
    parse_semver,
)


def order(parser, a: str, b: str) -> str:
    ka, kb = parser(a), parser(b)
    return "<" if ka < kb else (">" if ka > kb else "==")


@pytest.mark.parametrize(
    ("a", "expected", "b"),
    [
        ("1.0.0", "<", "1.0.1"),
        ("1.2.9", "<", "1.2.10"),          # numeric, not lexicographic
        ("2.0.0", "<", "10.0.0"),
        ("4.17.4", "<", "4.17.21"),
        ("1.0.0-rc1", "<", "1.0.0"),       # prerelease precedes release
        ("1.0.0-alpha.1", "<", "1.0.0-alpha.2"),
        ("1.0.0", "==", "1.0.0+build.5"),  # build metadata is not ordered
        ("1.0", "==", "1.0.0"),
    ],
)
def test_semver_ordering(a: str, expected: str, b: str) -> None:
    assert order(parse_semver, a, b) == expected


def test_semver_tolerates_non_registry_specifiers() -> None:
    # Lockfiles contain git URLs and file: references; these must not explode.
    for value in ("git+https://github.com/a/b.git", "file:../local", "workspace:*"):
        assert parse_semver(value) is not None


@pytest.mark.parametrize(
    ("a", "expected", "b"),
    [("1.9", "<", "1.10"), ("2.0.0rc1", "<", "2.0.0"), ("1.0", "<", "1.0.1")],
)
def test_pep440_ordering(a: str, expected: str, b: str) -> None:
    assert order(parse_pep440, a, b) == expected


@pytest.mark.parametrize(
    ("a", "expected", "b"),
    [
        ("1.0.0.beta", "<", "1.0.0"),  # a string segment makes it a prerelease
        ("2.0.9", "<", "2.1"),
        ("1.0", "==", "1.0.0"),        # missing trailing segments are zero
        ("1.2.3.rc1", "<", "1.2.3"),
    ],
)
def test_gem_ordering(a: str, expected: str, b: str) -> None:
    assert order(parse_gem_version, a, b) == expected


@pytest.mark.parametrize(
    ("a", "expected", "b"),
    [
        ("1.0-SNAPSHOT", "<", "1.0"),
        ("1.0-alpha", "<", "1.0-beta"),
        ("1.0-rc1", "<", "1.0-rc2"),
        ("1.0", "<", "1.0-sp"),        # service pack follows the release
        ("1.0-foo", "<", "1.0"),       # unknown qualifiers still precede release
        ("2.9.10", "<", "2.14.0"),
        ("1.0", "==", "1.0.0"),
        ("2.9.9.2", "<", "2.9.10.4"),  # the real jackson-databind upgrade path
    ],
)
def test_maven_ordering(a: str, expected: str, b: str) -> None:
    assert order(parse_maven_version, a, b) == expected
