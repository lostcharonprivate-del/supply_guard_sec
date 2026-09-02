"""End-to-end scanner behaviour.

Runs offline so the suite stays deterministic: the offline path exercises
routing, parsing, deduplication, ordering and scoring without depending on what
OSV or a registry returns today. Network behaviour is covered by tests marked
`network`, which are skipped by default.
"""

from __future__ import annotations

import pytest

from supplyguard.core.types import SEVERITY_ORDER, ScanStatus
from supplyguard.scanner import Scanner, ScanRequest
from tests.conftest import load_fixture


@pytest.fixture
async def scanner():
    async with Scanner() as instance:
        yield instance


class TestRoutingAndParsing:
    async def test_scans_every_ecosystem_in_one_request(self, scanner: Scanner) -> None:
        result = await scanner.scan(
            ScanRequest(
                files={
                    "package-lock.json": load_fixture("npm", "package-lock.json"),
                    "requirements.txt": load_fixture("pypi", "requirements.txt"),
                    "Gemfile.lock": load_fixture("rubygems", "Gemfile.lock"),
                    "pom.xml": load_fixture("maven", "pom.xml"),
                },
                offline=True,
            )
        )
        assert result.status is ScanStatus.COMPLETED
        assert {e.ecosystem for e in result.ecosystems} == {"npm", "pypi", "rubygems", "maven"}
        assert result.package_count > 250

    async def test_lockfile_supersedes_its_loose_manifest(self, scanner: Scanner) -> None:
        """Counting both would double-report every package and inflate the score."""
        result = await scanner.scan(
            ScanRequest(
                files={
                    "package-lock.json": load_fixture("npm", "package-lock.json"),
                    "package.json": load_fixture("npm", "package.json"),
                },
                offline=True,
            )
        )
        assert [e.manifest_filename for e in result.ecosystems] == ["package-lock.json"]
        assert any("Ignored package.json" in n for n in result.notes)

    async def test_ecosystem_filter_is_respected(self, scanner: Scanner) -> None:
        result = await scanner.scan(
            ScanRequest(
                files={
                    "package-lock.json": load_fixture("npm", "package-lock.json"),
                    "pom.xml": load_fixture("maven", "pom.xml"),
                },
                ecosystems=["maven"],
                offline=True,
            )
        )
        assert {e.ecosystem for e in result.ecosystems} == {"maven"}

    async def test_unsupported_files_are_reported_not_crashed_on(self, scanner: Scanner) -> None:
        result = await scanner.scan(
            ScanRequest(files={"go.mod": "module example.com/x\n"}, offline=True)
        )
        assert result.status is ScanStatus.COMPLETED
        assert result.findings == []
        assert any("No supported manifest" in n for n in result.notes)

    async def test_a_malformed_manifest_does_not_abort_the_others(
        self, scanner: Scanner
    ) -> None:
        result = await scanner.scan(
            ScanRequest(
                files={
                    "package-lock.json": "{ this is not json",
                    "pom.xml": load_fixture("maven", "pom.xml"),
                },
                offline=True,
            )
        )
        assert result.status is ScanStatus.COMPLETED
        assert any("package-lock.json" in e for e in result.errors)
        assert {e.ecosystem for e in result.ecosystems} == {"maven"}


class TestOfflineMode:
    async def test_offline_skips_network_detectors_and_says_so(self, scanner: Scanner) -> None:
        result = await scanner.scan(
            ScanRequest(
                files={"package-lock.json": load_fixture("npm", "package-lock.json")},
                offline=True,
            )
        )
        assert "vulnerability" not in result.detectors_run
        assert "typosquat" in result.detectors_run
        assert any("Offline mode" in n for n in result.notes)

    async def test_offline_repository_scan_fails_cleanly(self, scanner: Scanner) -> None:
        result = await scanner.scan(
            ScanRequest(repository_url="octocat/hello-world", offline=True)
        )
        assert result.status is ScanStatus.FAILED
        assert result.errors


class TestOrderingAndScoring:
    async def test_findings_are_ordered_by_actionability(self, scanner: Scanner) -> None:
        result = await scanner.scan(
            ScanRequest(
                files={"package-lock.json": load_fixture("npm", "package-lock.json")},
                offline=True,
            )
        )
        ranks = [SEVERITY_ORDER.index(f.severity) for f in result.findings]
        assert ranks == sorted(ranks), "findings must be sorted worst-first"

    async def test_result_serialises_for_the_api(self, scanner: Scanner) -> None:
        result = await scanner.scan(
            ScanRequest(
                files={"pom.xml": load_fixture("maven", "pom.xml")},
                offline=True,
                project_name="fixture",
            )
        )
        payload = result.summary()
        assert payload["project_name"] == "fixture"
        assert payload["risk"]["grade"] in {"A", "B", "C", "D", "F"}
        assert isinstance(payload["ecosystems"], list)


@pytest.mark.network
class TestLive:
    """Hits real APIs. Run with `pytest -m network`."""

    async def test_known_vulnerable_lockfile_produces_advisories(
        self, scanner: Scanner
    ) -> None:
        result = await scanner.scan(
            ScanRequest(
                files={"package-lock.json": load_fixture("npm", "package-lock.json")},
                detectors=["vulnerability"],
            )
        )
        identifiers = {f.identifier for f in result.findings}
        # minimist 1.2.0 is affected by this prototype-pollution advisory.
        assert "CVE-2021-44906" in identifiers
        fix = next(f for f in result.findings if f.identifier == "CVE-2021-44906")
        # The 1.x branch fix, not the 0.2.x one: recommending 0.2.1 to someone
        # on 1.2.0 would be advice to downgrade.
        assert fix.fixed_version == "1.2.6"

    async def test_known_malicious_release_is_categorised_as_malicious(
        self, scanner: Scanner
    ) -> None:
        result = await scanner.scan(
            ScanRequest(
                files={
                    "package-lock.json": (
                        '{"lockfileVersion": 3, "packages": {'
                        '"": {"dependencies": {"event-stream": "3.3.6"}},'
                        '"node_modules/event-stream": {"version": "3.3.6"}}}'
                    )
                },
                detectors=["malicious"],
            )
        )
        assert result.findings
        assert result.findings[0].category.value == "malicious"
        assert result.risk is not None and result.risk.grade == "F"
