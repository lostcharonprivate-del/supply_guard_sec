"""OSV advisory normalisation.

Uses real OSV document shapes. The multi-branch case is the important one: an
advisory covering several release branches must yield the fix for the branch
the scanned version is actually on.
"""

from __future__ import annotations

import pytest

from supplyguard.clients.osv import Vulnerability, parse_vulnerability
from supplyguard.core.types import PackageRef, Severity
from supplyguard.detectors.vulnerability import _dedupe

# GHSA-vh95-rmgr-6w4m, trimmed. minimist is maintained on two branches, each
# with its own fix: 0.2.1 on the 0.x line and 1.2.3 on the 1.x line.
MINIMIST_DOC = {
    "id": "GHSA-vh95-rmgr-6w4m",
    "summary": "Prototype Pollution in minimist",
    "aliases": ["CVE-2020-7598"],
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N"}],
    "database_specific": {"severity": "MODERATE", "cwe_ids": ["CWE-1321"]},
    "affected": [
        {
            "package": {"name": "minimist", "ecosystem": "npm"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.2.1"}]}],
        },
        {
            "package": {"name": "minimist", "ecosystem": "npm"},
            "ranges": [
                {"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.2.3"}]}
            ],
        },
    ],
    "references": [{"type": "WEB", "url": "https://example.invalid/advisory"}],
    "published": "2020-04-15T00:00:00Z",
}

# A Maven advisory covering several artifacts, only one of which is scanned.
MULTI_PACKAGE_DOC = {
    "id": "GHSA-multi",
    "summary": "Something in a Spring module",
    "affected": [
        {
            "package": {"name": "org.springframework:spring-web", "ecosystem": "Maven"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.3.0"}]}],
        },
        {
            "package": {"name": "org.springframework:spring-core", "ecosystem": "Maven"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.2.9"}]}],
        },
    ],
}


class TestRangeResolution:
    def test_selects_the_branch_containing_the_scanned_version(self) -> None:
        on_one_x = parse_vulnerability(MINIMIST_DOC, PackageRef("npm", "minimist", "1.2.0"))
        assert on_one_x.fixed_version == "1.2.3"

    def test_selects_the_other_branch_for_an_older_version(self) -> None:
        on_zero_x = parse_vulnerability(MINIMIST_DOC, PackageRef("npm", "minimist", "0.2.0"))
        assert on_zero_x.fixed_version == "0.2.1"

    def test_never_recommends_a_downgrade(self) -> None:
        """The regression this test exists for: telling a 1.2.0 user to install 0.2.1."""
        result = parse_vulnerability(MINIMIST_DOC, PackageRef("npm", "minimist", "1.2.0"))
        assert result.fixed_version is not None
        assert result.fixed_version.startswith("1.")

    def test_matches_the_right_package_in_a_multi_artifact_advisory(self) -> None:
        result = parse_vulnerability(
            MULTI_PACKAGE_DOC,
            PackageRef("Maven", "org.springframework:spring-core", "5.2.0"),
        )
        assert result.fixed_version == "5.2.9"

    def test_unrelated_package_yields_no_range(self) -> None:
        result = parse_vulnerability(
            MULTI_PACKAGE_DOC, PackageRef("Maven", "com.other:thing", "1.0")
        )
        assert result.fixed_version is None and result.affected_range is None


class TestNormalisation:
    def test_cvss_vector_is_scored_locally(self) -> None:
        result = parse_vulnerability(MINIMIST_DOC, PackageRef("npm", "minimist", "1.2.0"))
        assert result.cvss_score == 5.9
        assert result.severity is Severity.MEDIUM

    def test_cve_alias_is_preferred_as_the_public_identifier(self) -> None:
        result = parse_vulnerability(MINIMIST_DOC, PackageRef("npm", "minimist", "1.2.0"))
        assert result.primary_id == "CVE-2020-7598"

    def test_falls_back_to_the_advisory_label_without_a_vector(self) -> None:
        doc = {"id": "GHSA-x", "summary": "s", "database_specific": {"severity": "HIGH"}}
        result = parse_vulnerability(doc, PackageRef("npm", "p", "1.0.0"))
        assert result.severity is Severity.HIGH and result.cvss_score is None

    def test_summary_falls_back_to_the_first_line_of_details(self) -> None:
        doc = {"id": "GHSA-y", "details": "## Heading\n\nThe actual description."}
        result = parse_vulnerability(doc, PackageRef("npm", "p", "1.0.0"))
        assert result.summary == "Heading"


class TestMaliciousClassification:
    def test_mal_prefix_is_malicious(self) -> None:
        result = parse_vulnerability({"id": "MAL-2024-1"}, PackageRef("npm", "p", "1.0"))
        assert result.is_malicious
        assert "ossf/malicious-packages" in result.malicious_source

    def test_cwe_506_is_malicious(self) -> None:
        """How the GitHub Advisory Database tags event-stream and ua-parser-js."""
        doc = {"id": "GHSA-z", "database_specific": {"cwe_ids": ["CWE-506"]}}
        result = parse_vulnerability(doc, PackageRef("npm", "p", "1.0"))
        assert result.is_malicious
        assert "CWE-506" in result.malicious_source

    def test_ordinary_cve_is_not_malicious(self) -> None:
        result = parse_vulnerability(MINIMIST_DOC, PackageRef("npm", "minimist", "1.2.0"))
        assert not result.is_malicious


class TestDeduplication:
    def _vuln(self, **kwargs) -> Vulnerability:
        defaults = dict(id="GHSA-a", summary="s", details="d", aliases=["CVE-2020-1"])
        defaults.update(kwargs)
        return Vulnerability(**defaults)  # type: ignore[arg-type]

    def test_same_cve_from_two_databases_collapses(self) -> None:
        """OSV aggregates sources, so one CVE often arrives as GHSA and PYSEC."""
        merged = _dedupe(
            [self._vuln(id="GHSA-a"), self._vuln(id="PYSEC-2020-1")]
        )
        assert len(merged) == 1

    def test_the_entry_with_a_fix_version_wins(self) -> None:
        merged = _dedupe(
            [
                self._vuln(id="GHSA-a", fixed_version=None),
                self._vuln(id="PYSEC-1", fixed_version="2.0.0"),
            ]
        )
        assert merged[0].fixed_version == "2.0.0"

    def test_distinct_cves_are_kept(self) -> None:
        merged = _dedupe(
            [self._vuln(aliases=["CVE-2020-1"]), self._vuln(id="GHSA-b", aliases=["CVE-2020-2"])]
        )
        assert len(merged) == 2

    def test_result_is_ordered_worst_first(self) -> None:
        merged = _dedupe(
            [
                self._vuln(id="a", aliases=["CVE-1"], severity=Severity.LOW),
                self._vuln(id="b", aliases=["CVE-2"], severity=Severity.CRITICAL),
            ]
        )
        assert merged[0].severity is Severity.CRITICAL


@pytest.mark.parametrize("withdrawn", ["2021-01-01T00:00:00Z", None])
def test_withdrawn_field_is_parsed(withdrawn: str | None) -> None:
    doc = {"id": "GHSA-w", "summary": "s", "withdrawn": withdrawn}
    result = parse_vulnerability(doc, PackageRef("npm", "p", "1.0"))
    assert (result.withdrawn is not None) == (withdrawn is not None)
