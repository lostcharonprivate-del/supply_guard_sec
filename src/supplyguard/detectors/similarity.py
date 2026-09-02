"""Name-similarity primitives for typosquatting detection.

Every function here is pure and side-effect free, which is deliberate: this is
the part of the system with real algorithmic content, and it should be provable
against known-typosquat examples without a network or a database.

The detector combines several independent signals rather than relying on edit
distance alone, because edit distance on its own is a poor typosquat detector:
`react` and `preact` are one character apart and both legitimate, while
`electron` and `electorn` are a transposition that reads almost identically.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from enum import StrEnum

# --------------------------------------------------------------------------
# Signal taxonomy
# --------------------------------------------------------------------------


class SignalKind(StrEnum):
    EDIT_DISTANCE = "edit_distance"
    TRANSPOSITION = "transposition"
    REPEATED_CHARACTER = "repeated_character"
    OMITTED_CHARACTER = "omitted_character"
    KEYBOARD_ADJACENT = "keyboard_adjacent"
    HOMOGLYPH = "homoglyph"
    ASCII_LOOKALIKE = "ascii_lookalike"
    SEPARATOR_SWAP = "separator_swap"
    PLURALISATION = "pluralisation"
    SCOPE_CONFUSION = "scope_confusion"
    SPELLING_VARIANT = "spelling_variant"
    DIGIT_VARIANT = "digit_variant"
    AFFIX = "affix"


@dataclass(frozen=True, slots=True)
class Signal:
    """One reason to believe `candidate` is imitating `reference`."""

    kind: SignalKind
    #: 0.0-1.0. How strongly this signal alone implies imitation.
    strength: float
    explanation: str


# --------------------------------------------------------------------------
# Edit distances
# --------------------------------------------------------------------------


def levenshtein(a: str, b: str, max_distance: int | None = None) -> int:
    """Levenshtein distance, with an optional early-exit bound.

    The bound matters: a scan compares a few hundred dependencies against a
    2,000-name reference set, and most pairs can be rejected on length alone.
    Returns ``max_distance + 1`` when the true distance exceeds the bound.
    """
    if a == b:
        return 0
    if max_distance is not None and abs(len(a) - len(b)) > max_distance:
        return max_distance + 1
    if not a:
        return len(b)
    if not b:
        return len(a)

    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        row_min = i
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            value = min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost)
            current.append(value)
            row_min = min(row_min, value)
        previous = current
        if max_distance is not None and row_min > max_distance:
            return max_distance + 1
    return previous[-1]


def damerau_levenshtein(a: str, b: str) -> int:
    """Optimal string alignment distance — Levenshtein plus transpositions.

    Transposed adjacent characters (`electorn` for `electron`) are one of the
    most common real typos and read as almost identical, so counting them as a
    single edit rather than two is what makes them rank alongside substitutions.
    """
    if a == b:
        return 0
    len_a, len_b = len(a), len(b)
    if not len_a:
        return len_b
    if not len_b:
        return len_a

    matrix = [[0] * (len_b + 1) for _ in range(len_a + 1)]
    for i in range(len_a + 1):
        matrix[i][0] = i
    for j in range(len_b + 1):
        matrix[0][j] = j

    for i in range(1, len_a + 1):
        for j in range(1, len_b + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            matrix[i][j] = min(
                matrix[i - 1][j] + 1,
                matrix[i][j - 1] + 1,
                matrix[i - 1][j - 1] + cost,
            )
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                matrix[i][j] = min(matrix[i][j], matrix[i - 2][j - 2] + 1)
    return matrix[len_a][len_b]


def is_transposition(a: str, b: str) -> bool:
    """True when `a` is `b` with exactly one adjacent pair swapped."""
    if len(a) != len(b) or a == b:
        return False
    diffs = [i for i, (x, y) in enumerate(zip(a, b, strict=True)) if x != y]
    if len(diffs) != 2:
        return False
    i, j = diffs
    return j == i + 1 and a[i] == b[j] and a[j] == b[i]


def repeated_character_variant(a: str, b: str) -> bool:
    """True when the names differ only by a doubled character (`expresss`)."""
    if a == b:
        return False
    return _collapse_runs(a) == _collapse_runs(b)


def _collapse_runs(value: str) -> str:
    return re.sub(r"(.)\1+", r"\1", value)


# --------------------------------------------------------------------------
# Keyboard adjacency
# --------------------------------------------------------------------------

#: QWERTY neighbours, including the diagonals a finger actually slips onto.
_QWERTY_ROWS = ["`1234567890-=", "qwertyuiop[]\\", "asdfghjkl;'", "zxcvbnm,./"]
#: Horizontal offset of each row relative to the one above it.
_ROW_OFFSET = [0.0, 0.5, 0.75, 1.25]


def _build_adjacency() -> dict[str, set[str]]:
    """Map each key to the keys a finger can physically slip onto.

    Rows are offset horizontally the way a real keyboard staggers them, so that
    `s` counts as adjacent to `w` and `e` but not to `r`.
    """
    positions: dict[str, tuple[float, float]] = {}
    for row_index, row_keys in enumerate(_QWERTY_ROWS):
        for col_index, char in enumerate(row_keys):
            positions[char] = (float(row_index), col_index + _ROW_OFFSET[row_index])

    adjacency: dict[str, set[str]] = {}
    for char, (char_row, char_col) in positions.items():
        adjacency[char] = {
            other
            for other, (other_row, other_col) in positions.items()
            if other != char
            and abs(other_row - char_row) <= 1
            and abs(other_col - char_col) <= 1.0
        }
    return adjacency


KEYBOARD_ADJACENCY: dict[str, set[str]] = _build_adjacency()


def are_keyboard_adjacent(a: str, b: str) -> bool:
    return b in KEYBOARD_ADJACENCY.get(a, set())


def keyboard_typo_distance(a: str, b: str) -> float | None:
    """Cost of turning `a` into `b` using only keyboard-plausible slips.

    Returns None when the names differ by something other than same-length
    single-character substitutions — this is a targeted check for "fat finger"
    squats (`expresss`/`exprese`, `numpu`/`numpy`), not a general metric.
    """
    if len(a) != len(b):
        return None
    diffs = [(x, y) for x, y in zip(a, b, strict=True) if x != y]
    if not diffs or len(diffs) > 2:
        return None
    total = 0.0
    for x, y in diffs:
        if are_keyboard_adjacent(x, y):
            total += 0.5
        else:
            return None
    return total


# --------------------------------------------------------------------------
# Homoglyphs
# --------------------------------------------------------------------------

#: Non-Latin characters that render as Latin letters in most fonts. This is the
#: practically-exploited subset of the Unicode confusables table, not the whole
#: thing — Cyrillic and Greek cover the overwhelming majority of real cases.
_UNICODE_CONFUSABLES: dict[str, str] = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "х": "x", "у": "y", "і": "i", "ѕ": "s", "ј": "j",
    "ӏ": "l", "һ": "h", "ԁ": "d", "к": "k", "м": "m",
    "в": "b", "н": "h", "т": "t", "г": "r", "А": "a",
    "В": "b", "Е": "e", "К": "k", "М": "m", "Н": "h",
    "О": "o", "Р": "p", "С": "c", "Т": "t", "Х": "x",
    # Greek
    "ο": "o", "α": "a", "ε": "e", "ι": "i", "κ": "k",
    "ν": "v", "ρ": "p", "τ": "t", "χ": "x", "γ": "y",
    "μ": "u", "Α": "a", "Β": "b", "Ε": "e", "Ζ": "z",
    "Η": "h", "Ι": "i", "Κ": "k", "Μ": "m", "Ν": "n",
    "Ο": "o", "Ρ": "p", "Τ": "t", "Υ": "y", "Χ": "x",
    # Armenian / other
    "ո": "n", "ռ": "n", "օ": "o", "ҽ": "e",
    # Latin extended lookalikes
    "ı": "i", "ł": "l", "ǀ": "l", "‐": "-", "‑": "-",
    "‒": "-", "–": "-", "—": "-", "−": "-",
}

#: Pairs that are confusable *within ASCII*. These matter more than Unicode
#: confusables in practice: npm and PyPI restrict names to ASCII, so a squatter
#: attacking those registries has to work with `rn`/`m`, `1`/`l`, `0`/`o`.
_ASCII_LOOKALIKE_SEQUENCES: list[tuple[str, str]] = [
    ("rn", "m"), ("vv", "w"), ("cl", "d"), ("nn", "m"),
]
_ASCII_LOOKALIKE_CHARS: dict[str, str] = {
    "0": "o", "1": "l", "5": "s", "2": "z", "8": "b",
}


def has_unicode_confusables(value: str) -> bool:
    """True when the name contains a non-ASCII character that renders as Latin."""
    return any(char in _UNICODE_CONFUSABLES for char in value) or any(
        ord(char) > 127 for char in value
    )


#: Folds that must run before lowercasing, or the confusion they encode is lost.
_CASE_SENSITIVE_FOLDS = str.maketrans({"I": "l", "|": "l", "\u0130": "l"})


def homoglyph_skeleton(value: str) -> str:
    """Reduce a name to a canonical form that collapses visual lookalikes.

    Two names with the same skeleton are visually confusable. Applied in order:
    NFKC (folds fullwidth and mathematical variants), the confusables table,
    then ASCII digit/sequence lookalikes.
    """
    text = unicodedata.normalize("NFKC", value)
    # Case-sensitive folds must happen *before* lowercasing, or the confusion
    # they encode is destroyed. Capital I, lowercase l and the digit 1 render
    # near-identically in most sans-serif fonts: `jeIlyfish` was a real 2019
    # PyPI package that stole SSH keys from anyone who fat-fingered `jellyfish`.
    text = text.translate(_CASE_SENSITIVE_FOLDS)
    text = text.lower()
    text = "".join(_UNICODE_CONFUSABLES.get(char, char) for char in text)
    # Strip combining marks left over from decomposition.
    text = "".join(c for c in unicodedata.normalize("NFKD", text) if not unicodedata.combining(c))
    for sequence, replacement in _ASCII_LOOKALIKE_SEQUENCES:
        text = text.replace(sequence, replacement)
    text = "".join(_ASCII_LOOKALIKE_CHARS.get(char, char) for char in text)
    return text


# --------------------------------------------------------------------------
# Structural variants
# --------------------------------------------------------------------------

_SEPARATORS = re.compile(r"[-_.]+")
#: Prefixes and suffixes squatters bolt onto a popular name to look official.
_AFFIXES = (
    "js", "node", "nodejs", "python", "py", "ruby", "rb", "java", "lib",
    "core", "cli", "api", "sdk", "utils", "util", "helper", "official",
    "new", "latest", "ng", "es", "ts", "go", "rs", "net", "dev", "pro",
)
#: An affix optionally carrying a version number, so that `python3-dateutil`
#: matches `dateutil` — the shape of the real 2019 PyPI attack, where
#: `python3-dateutil` shipped alongside a squat of `jellyfish`.
_AFFIX_RE = re.compile(
    r"^(?:" + "|".join(_AFFIXES) + r"|v)\d*$|^\d+$"
)


def normalise_separators(value: str) -> str:
    """`babel-core`, `babel_core` and `babel.core` all collapse to one form."""
    return _SEPARATORS.sub("-", value.strip().lower())


def separator_variant(a: str, b: str) -> bool:
    stripped_a = _SEPARATORS.sub("", a.lower())
    stripped_b = _SEPARATORS.sub("", b.lower())
    return a.lower() != b.lower() and stripped_a == stripped_b


def plural_variant(a: str, b: str) -> bool:
    """`request` vs `requests`, `util` vs `utils`."""
    x, y = sorted((a.lower(), b.lower()), key=len)
    return y in (x + "s", x + "es") and x != y


def strip_scope(name: str) -> str:
    """`@babel/core` -> `babel/core`; `org.slf4j:slf4j-api` -> `slf4j-api`."""
    if name.startswith("@"):
        return name[1:]
    if ":" in name:
        return name.split(":", 1)[1]
    return name


def scope_confusion_variants(name: str) -> set[str]:
    """Names that a scoped package could be impersonated by, and vice versa.

    `@babel/core` and `babel-core` are the canonical example: the unscoped name
    is registerable by anyone, and reads as the official package.
    """
    variants: set[str] = set()
    lowered = name.lower()
    if lowered.startswith("@") and "/" in lowered:
        scope, _, package = lowered[1:].partition("/")
        variants.update({f"{scope}-{package}", f"{scope}_{package}", f"{scope}.{package}", package})
    elif "/" not in lowered and ":" not in lowered:
        for separator in ("-", "_", "."):
            if separator in lowered:
                head, _, tail = lowered.partition(separator)
                variants.add(f"@{head}/{tail}")
    return variants - {lowered}


def affix_variant(a: str, b: str) -> str | None:
    """Detect `X` vs `X-js` / `python3-X` style padding of a popular name.

    Returns the affix that was added, or None. The extra text is matched against
    a pattern rather than a fixed list so that versioned affixes (`python3`,
    `v2`) are recognised without enumerating every combination.
    """
    short, long = sorted((a.lower(), b.lower()), key=len)
    if short == long or not short:
        return None
    normalised_long = normalise_separators(long)
    normalised_short = normalise_separators(short)

    for separator in ("-", ""):
        if normalised_long.endswith(f"{separator}{normalised_short}"):
            prefix = normalised_long[: len(normalised_long) - len(normalised_short) - len(separator)]
            if prefix and _AFFIX_RE.match(prefix):
                return prefix
        if normalised_long.startswith(f"{normalised_short}{separator}"):
            suffix = normalised_long[len(normalised_short) + len(separator) :]
            if suffix and _AFFIX_RE.match(suffix):
                return suffix
    return None


#: Regional spelling pairs. `colourama` was a real malicious PyPI package
#: imitating `colorama`, and no edit-distance threshold flags it convincingly.
_SPELLING_SUBSTITUTIONS = (
    ("our", "or"), ("ise", "ize"), ("isation", "ization"),
    ("yse", "yze"), ("re", "er"), ("ll", "l"), ("ae", "e"), ("oe", "e"),
)


def digit_variant(a: str, b: str) -> bool:
    """True when two names differ only in their digits.

    `python3-dateutil` versus `python-dateutil` is exactly this shape, and it
    was a real 2019 PyPI attack that shipped alongside a `jellyfish` squat.
    Version-looking digits bolted onto a popular name read as an official
    successor and are trivially registerable.
    """
    stripped_a = re.sub(r"\d+", "", a.lower())
    stripped_b = re.sub(r"\d+", "", b.lower())
    return a.lower() != b.lower() and stripped_a == stripped_b and bool(stripped_a)


def spelling_variant(a: str, b: str) -> bool:
    """True when two names differ only by a regional spelling convention."""
    lowered_a, lowered_b = a.lower(), b.lower()
    if lowered_a == lowered_b:
        return False
    for british, american in _SPELLING_SUBSTITUTIONS:
        if lowered_a.replace(british, american) == lowered_b.replace(british, american):
            return True
    return False


# --------------------------------------------------------------------------
# Combined analysis
# --------------------------------------------------------------------------


def analyse_pair(candidate: str, reference: str, *, max_distance: int = 2) -> list[Signal]:
    """Every reason to believe `candidate` is imitating `reference`.

    An empty list means the names are unrelated (or identical — an exact match
    is not a squat).
    """
    if not candidate or not reference:
        return []
    lowered_candidate = candidate.lower()
    lowered_reference = reference.lower()
    if lowered_candidate == lowered_reference:
        return []

    signals: list[Signal] = []

    # -- visual confusability ------------------------------------------------
    skeleton_candidate = homoglyph_skeleton(candidate)
    skeleton_reference = homoglyph_skeleton(reference)
    if skeleton_candidate == skeleton_reference:
        if has_unicode_confusables(candidate):
            signals.append(
                Signal(
                    SignalKind.HOMOGLYPH,
                    0.98,
                    f"Contains non-ASCII characters that render identically to "
                    f"'{reference}'. The two names are visually indistinguishable.",
                )
            )
        else:
            signals.append(
                Signal(
                    SignalKind.ASCII_LOOKALIKE,
                    0.9,
                    f"Visually collides with '{reference}' using ASCII lookalikes "
                    f"(rn/m, 1/l, 0/o); both reduce to '{skeleton_candidate}'.",
                )
            )

    # -- structural variants -------------------------------------------------
    if separator_variant(lowered_candidate, lowered_reference):
        signals.append(
            Signal(
                SignalKind.SEPARATOR_SWAP,
                0.75,
                f"Differs from '{reference}' only in hyphen/underscore/dot "
                "separators, which read identically in a manifest.",
            )
        )

    if plural_variant(lowered_candidate, lowered_reference):
        signals.append(
            Signal(
                SignalKind.PLURALISATION,
                0.8,
                f"Singular/plural variant of '{reference}' — the mistake behind "
                "the real `python3-dateutil` and `requests`/`request` squats.",
            )
        )

    if lowered_candidate in scope_confusion_variants(reference) or lowered_reference in scope_confusion_variants(candidate):
        signals.append(
            Signal(
                SignalKind.SCOPE_CONFUSION,
                0.85,
                f"Scoped/unscoped confusion with '{reference}'. The unscoped form "
                "is registerable by anyone and reads as the official package.",
            )
        )

    if digit_variant(lowered_candidate, lowered_reference):
        signals.append(
            Signal(
                SignalKind.DIGIT_VARIANT,
                0.75,
                f"Differs from '{reference}' only in digits, reading as an "
                "official version successor. This is the `python3-dateutil` pattern.",
            )
        )

    if spelling_variant(lowered_candidate, lowered_reference):
        signals.append(
            Signal(
                SignalKind.SPELLING_VARIANT,
                0.8,
                f"Regional spelling variant of '{reference}' (colour/color, "
                "ise/ize). This is the `colourama` attack pattern.",
            )
        )

    if (affix := affix_variant(lowered_candidate, lowered_reference)) is not None:
        signals.append(
            Signal(
                SignalKind.AFFIX,
                0.6,
                f"'{reference}' padded with the affix '{affix}'. Legitimate ports "
                "use this pattern too, so this signal alone is weak.",
            )
        )

    # -- typo shapes ---------------------------------------------------------
    if is_transposition(lowered_candidate, lowered_reference):
        signals.append(
            Signal(
                SignalKind.TRANSPOSITION,
                0.85,
                f"Two adjacent characters swapped versus '{reference}'.",
            )
        )
    elif repeated_character_variant(lowered_candidate, lowered_reference):
        signals.append(
            Signal(
                SignalKind.REPEATED_CHARACTER,
                0.8,
                f"Differs from '{reference}' only by a doubled character.",
            )
        )
    else:
        keyboard = keyboard_typo_distance(lowered_candidate, lowered_reference)
        if keyboard is not None:
            signals.append(
                Signal(
                    SignalKind.KEYBOARD_ADJACENT,
                    0.82,
                    f"Every differing character versus '{reference}' is a "
                    "physically adjacent key on a QWERTY keyboard.",
                )
            )

    if len(lowered_candidate) == len(lowered_reference) - 1 and _is_deletion(
        lowered_candidate, lowered_reference
    ):
        signals.append(
            Signal(
                SignalKind.OMITTED_CHARACTER,
                0.7,
                f"'{reference}' with one character dropped.",
            )
        )

    # -- generic edit distance, as the fallback signal ------------------------
    distance = damerau_levenshtein(lowered_candidate, lowered_reference)
    if 0 < distance <= max_distance and not signals:
        shorter = min(len(lowered_candidate), len(lowered_reference))
        # One edit in a four-character name is a much weaker signal than one
        # edit in a twenty-character name.
        strength = 0.55 if distance == 1 else 0.4
        if shorter <= 5:
            strength -= 0.15
        signals.append(
            Signal(
                SignalKind.EDIT_DISTANCE,
                max(0.2, strength),
                f"Edit distance {distance} from '{reference}'.",
            )
        )
    return signals


def _is_deletion(shorter: str, longer: str) -> bool:
    """True when `shorter` is `longer` with exactly one character removed."""
    i = j = 0
    skipped = False
    while i < len(shorter) and j < len(longer):
        if shorter[i] == longer[j]:
            i += 1
            j += 1
        elif skipped:
            return False
        else:
            skipped = True
            j += 1
    return True
