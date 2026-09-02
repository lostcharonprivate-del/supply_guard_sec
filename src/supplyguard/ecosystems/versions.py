"""Sortable version keys per ecosystem.

Used only for staleness comparisons ("is something newer available?"). Matching
a version against a vulnerable *range* is delegated to OSV, which implements
each ecosystem's real range semantics — reimplementing four sets of range rules
would be a rich source of silent false negatives.
"""

from __future__ import annotations

import re

# A component that sorts below any real number, so that prereleases order
# before their release (1.0.0-rc1 < 1.0.0) as semver requires.
_LOWEST = (-1, "")


def _ident(part: str) -> tuple[int, str]:
    """Numeric identifiers compare numerically and rank below alphanumerics."""
    if part.isdigit():
        return (0, f"{int(part):020d}")
    return (1, part)


def parse_semver(version: str) -> tuple:
    """Sort key for a semver string, tolerant of the junk found in lockfiles."""
    text = str(version).strip().lstrip("v=")
    # Non-registry specifiers (git URLs, file:, npm: aliases) have no order.
    if not text or not text[0].isdigit():
        return ((0,), (1, text))
    core, _, rest = text.partition("+")  # build metadata is ignored for ordering
    core, _, prerelease = core.partition("-")
    numbers = tuple(int(p) if p.isdigit() else 0 for p in core.split(".")[:4])
    numbers = numbers + (0,) * (3 - len(numbers)) if len(numbers) < 3 else numbers
    if prerelease:
        pre = tuple(_ident(p) for p in prerelease.split("."))
        return (numbers, (0,), pre)
    return (numbers, (1,), ())


def parse_pep440(version: str) -> tuple:
    """Sort key for a Python version, via `packaging` with a safe fallback."""
    from packaging.version import InvalidVersion, Version

    try:
        v = Version(str(version))
    except InvalidVersion:
        return ((0,), (1, str(version)))
    return ((1,), v.release, (0,) if v.is_prerelease else (1,), str(v))


def parse_gem_version(version: str) -> tuple:
    """Sort key for a RubyGems version.

    Gem::Version orders segment-by-segment; a string segment (`1.0.0.beta`)
    sorts *before* the same version without it, and missing trailing segments
    are treated as zero (`1.0` == `1.0.0`). Both fall out of padding every key
    to a fixed width with a neutral element that equals numeric zero.
    """
    segments = re.findall(r"\d+|[A-Za-z]+", str(version).strip())
    key: list[tuple[int, int, str]] = []
    for seg in segments[:_WIDTH]:
        if seg.isdigit():
            key.append((_NUMERIC, int(seg), ""))
        else:
            # Any alphabetic segment makes the version a prerelease.
            key.append((_PRE, 0, seg))
    return tuple(_pad(key))


#: Element kinds, ordered. A prerelease qualifier sorts below numeric zero
#: (so `1.0-rc1 < 1.0`); a post-release qualifier sorts above it.
_PRE, _NUMERIC, _POST = 0, 1, 2
_NEUTRAL = (_NUMERIC, 0, "")
_WIDTH = 12


def _pad(key: list[tuple[int, int, str]]) -> list[tuple[int, int, str]]:
    """Pad to a fixed width so keys of different lengths compare correctly."""
    return key + [_NEUTRAL] * (_WIDTH - len(key))


#: Maven's well-known qualifiers and their order relative to a plain release.
_MAVEN_QUALIFIERS: dict[str, tuple[int, int]] = {
    "alpha": (_PRE, -6), "a": (_PRE, -6),
    "beta": (_PRE, -5), "b": (_PRE, -5),
    "milestone": (_PRE, -4), "m": (_PRE, -4),
    "rc": (_PRE, -3), "cr": (_PRE, -3),
    "snapshot": (_PRE, -2),
    "ga": (_NUMERIC, 0), "final": (_NUMERIC, 0), "release": (_NUMERIC, 0),
    "sp": (_POST, 1),
}


def parse_maven_version(version: str) -> tuple:
    """Sort key for a Maven version.

    Implements the practically-relevant part of Maven's ComparableVersion:
    dot/dash separated tokens, numeric tokens compared numerically, and the
    qualifier ordering where alpha/beta/milestone/rc/SNAPSHOT precede a release
    while `sp` follows it. Unknown qualifiers sort after all known ones but
    still before a plain release, compared alphabetically — Maven's own rule.
    """
    tokens = [t for t in re.split(r"[.\-_]", str(version).strip().lower()) if t]
    key: list[tuple[int, int, str]] = []
    for token in tokens[:_WIDTH]:
        if token.isdigit():
            key.append((_NUMERIC, int(token), ""))
            continue
        # Split trailing digits off qualifiers such as `rc1` / `beta2`.
        match = re.fullmatch(r"([a-z]+)(\d+)", token)
        word, trailing = (match.group(1), int(match.group(2))) if match else (token, 0)
        kind, rank = _MAVEN_QUALIFIERS.get(word, (_PRE, 100))
        text = "" if word in _MAVEN_QUALIFIERS else word
        key.append((kind, rank, text))
        if trailing:
            key.append((_NUMERIC, trailing, ""))
    return tuple(_pad(key))
