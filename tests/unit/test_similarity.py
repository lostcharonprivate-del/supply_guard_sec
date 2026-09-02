"""Name-similarity primitives, validated against documented typosquat incidents."""

from __future__ import annotations

import pytest

from supplyguard.detectors.similarity import (
    SignalKind,
    analyse_pair,
    damerau_levenshtein,
    homoglyph_skeleton,
    is_transposition,
    keyboard_typo_distance,
    levenshtein,
    plural_variant,
    scope_confusion_variants,
    separator_variant,
    spelling_variant,
)


class TestEditDistance:
    @pytest.mark.parametrize(
        ("a", "b", "expected"),
        [("", "", 0), ("abc", "abc", 0), ("abc", "abd", 1), ("abc", "", 3), ("kitten", "sitting", 3)],
    )
    def test_levenshtein(self, a: str, b: str, expected: int) -> None:
        assert levenshtein(a, b) == expected

    def test_bound_short_circuits_without_lying_about_close_pairs(self) -> None:
        # Beyond the bound the exact value does not matter, only that it exceeds.
        assert levenshtein("kitten", "sitting", max_distance=1) > 1
        assert levenshtein("abc", "abd", max_distance=1) == 1

    def test_damerau_counts_a_transposition_as_one_edit(self) -> None:
        assert damerau_levenshtein("reqeusts", "requests") == 1
        assert levenshtein("reqeusts", "requests") == 2


class TestTypoShapes:
    def test_transposition(self) -> None:
        assert is_transposition("electorn", "electron")
        assert not is_transposition("electron", "electron")
        assert not is_transposition("react", "preact")

    def test_keyboard_adjacency(self) -> None:
        # 'y' and 't' are adjacent; 'y' and 'q' are not.
        assert keyboard_typo_distance("numpt", "numpy") is not None
        assert keyboard_typo_distance("numpq", "numpy") is None

    def test_separator_and_plural_variants(self) -> None:
        assert separator_variant("cross-env", "cross_env")
        assert plural_variant("request", "requests")
        assert not plural_variant("requests", "requests")

    def test_spelling_variant_catches_colourama(self) -> None:
        assert spelling_variant("colourama", "colorama")


class TestHomoglyphs:
    def test_cyrillic_folds_to_latin(self) -> None:
        cyrillic_a = "а"
        assert homoglyph_skeleton(f"p{cyrillic_a}ndas") == "pandas"

    def test_ascii_lookalikes_collide(self) -> None:
        assert homoglyph_skeleton("rnicrosoft") == homoglyph_skeleton("microsoft")
        assert homoglyph_skeleton("c0lorama") == homoglyph_skeleton("colorama")

    def test_capital_i_folds_before_lowercasing(self) -> None:
        # The real 2019 jeIlyfish attack: capital I standing in for lowercase l.
        # Lowercasing first would destroy exactly this confusion.
        assert homoglyph_skeleton("jeIlyfish") == homoglyph_skeleton("jellyfish")

    def test_unrelated_names_do_not_collide(self) -> None:
        assert homoglyph_skeleton("django") != homoglyph_skeleton("flask")


class TestScopeConfusion:
    def test_scoped_to_unscoped(self) -> None:
        assert "babel-core" in scope_confusion_variants("@babel/core")

    def test_unscoped_to_scoped(self) -> None:
        assert "@babel/core" in scope_confusion_variants("babel-core")


class TestKnownIncidents:
    """Every pair here is a documented real-world typosquat."""

    @pytest.mark.parametrize(
        ("squat", "target", "expected_signal"),
        [
            ("crossenv", "cross-env", SignalKind.SEPARATOR_SWAP),
            ("reqeusts", "requests", SignalKind.TRANSPOSITION),
            ("colourama", "colorama", SignalKind.SPELLING_VARIANT),
            ("jeIlyfish", "jellyfish", SignalKind.ASCII_LOOKALIKE),
            ("python3-dateutil", "python-dateutil", SignalKind.DIGIT_VARIANT),
            ("urlib3", "urllib3", SignalKind.REPEATED_CHARACTER),
            ("babel-core", "@babel/core", SignalKind.SCOPE_CONFUSION),
        ],
    )
    def test_incident_is_detected_with_the_right_signal(
        self, squat: str, target: str, expected_signal: SignalKind
    ) -> None:
        signals = analyse_pair(squat, target)
        assert signals, f"{squat} vs {target} produced no signal"
        assert expected_signal in {s.kind for s in signals}

    @pytest.mark.parametrize(
        ("a", "b"),
        [
            ("requests", "requests"),   # identical is not a squat
            ("django", "flask"),        # unrelated
            ("numpy", "pandas"),
        ],
    )
    def test_unrelated_or_identical_names_produce_no_signal(self, a: str, b: str) -> None:
        assert analyse_pair(a, b) == []

    def test_short_names_are_scored_more_cautiously(self) -> None:
        """One edit in a short name is weaker evidence than one in a long name.

        Short names collide by chance far more often. The penalty applies to
        the generic edit-distance fallback, so the pairs here use characters
        that are not keyboard-adjacent — otherwise a stronger, more specific
        signal fires instead and there is no fallback left to compare.
        """
        def edit_strength(a: str, b: str) -> float:
            signals = [s for s in analyse_pair(a, b) if s.kind is SignalKind.EDIT_DISTANCE]
            assert signals, f"expected an edit-distance signal for {a} vs {b}"
            return signals[0].strength

        assert edit_strength("abca", "abcp") < edit_strength("abcdefghijka", "abcdefghijkp")
