"""GitHub Actions workflow analysis and CI monitoring."""

from __future__ import annotations

import pytest

from supplyguard.ci.monitor import CiMonitorResult
from supplyguard.ci.workflow_analysis import analyse_workflow
from supplyguard.core.types import Severity

PATH = ".github/workflows/ci.yml"


def rules(content: str) -> set[str]:
    return {issue.rule for issue in analyse_workflow(PATH, content)}


class TestActionPinning:
    def test_a_mutable_tag_on_a_third_party_action_is_flagged(self) -> None:
        content = """
        on: push
        permissions: {contents: read}
        jobs:
          build:
            steps:
              - uses: tj-actions/changed-files@v35
        """
        issues = analyse_workflow(PATH, content)
        pinning = [i for i in issues if i.rule == "action_not_pinned"]
        assert len(pinning) == 1
        assert pinning[0].severity is Severity.MEDIUM

    def test_a_sha_pinned_action_is_not_flagged(self) -> None:
        content = """
        on: push
        permissions: {contents: read}
        jobs:
          build:
            steps:
              - uses: actions/setup-node@8f152de45cc393bb48ce5d89d36b731f54556e65
        """
        assert "action_not_pinned" not in rules(content)

    def test_github_owned_actions_rank_lower_than_third_party(self) -> None:
        content = """
        on: push
        permissions: {contents: read}
        jobs:
          build:
            steps:
              - uses: actions/checkout@v4
              - uses: random-vendor/thing@v1
        """
        by_action = {
            i.details["action"]: i.severity
            for i in analyse_workflow(PATH, content)
            if i.rule == "action_not_pinned"
        }
        assert by_action["actions/checkout"] is Severity.LOW
        assert by_action["random-vendor/thing"] is Severity.MEDIUM

    def test_local_actions_are_ignored(self) -> None:
        content = """
        on: push
        permissions: {contents: read}
        jobs:
          build:
            steps:
              - uses: ./.github/actions/setup
        """
        assert "action_not_pinned" not in rules(content)


class TestSecretExposure:
    def test_secrets_to_an_unpinned_third_party_action_are_flagged(self) -> None:
        content = """
        on: push
        permissions: {contents: read}
        jobs:
          publish:
            steps:
              - uses: some-vendor/publish@v1
                with:
                  token: ${{ secrets.NPM_TOKEN }}
        """
        issues = [i for i in analyse_workflow(PATH, content) if i.rule == "secret_to_unpinned_action"]
        assert len(issues) == 1
        assert "NPM_TOKEN" in issues[0].details["secrets"]

    def test_secrets_to_a_sha_pinned_action_are_not_flagged(self) -> None:
        content = """
        on: push
        permissions: {contents: read}
        jobs:
          publish:
            steps:
              - uses: some-vendor/publish@1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b
                with:
                  token: ${{ secrets.NPM_TOKEN }}
        """
        assert "secret_to_unpinned_action" not in rules(content)


class TestScriptInjection:
    def test_untrusted_context_in_a_run_block_is_flagged(self) -> None:
        content = """
        on: issues
        permissions: {contents: read}
        jobs:
          greet:
            steps:
              - run: echo "Thanks ${{ github.event.issue.title }}"
        """
        issues = [i for i in analyse_workflow(PATH, content) if i.rule == "script_injection"]
        assert len(issues) == 1
        assert issues[0].severity is Severity.HIGH

    def test_a_safe_context_is_not_flagged(self) -> None:
        content = """
        on: push
        permissions: {contents: read}
        jobs:
          build:
            steps:
              - run: echo "Building ${{ github.sha }} on ${{ github.repository }}"
        """
        assert "script_injection" not in rules(content)


class TestPermissions:
    def test_write_all_is_flagged(self) -> None:
        content = "on: push\npermissions: write-all\njobs:\n  b:\n    steps:\n      - run: echo hi\n"
        assert "permissions_write_all" in rules(content)

    def test_an_explicit_narrow_grant_is_not_flagged(self) -> None:
        content = (
            "on: push\npermissions: {contents: read}\njobs:\n  b:\n    steps:\n      - run: echo hi\n"
        )
        assert not rules(content) & {"permissions_write_all", "permissions_unset"}

    def test_an_empty_permissions_block_counts_as_declared(self) -> None:
        # `permissions: {}` is the most restrictive setting there is, and is
        # what hardened repositories actually use.
        content = "on: push\npermissions: {}\njobs:\n  b:\n    steps:\n      - run: echo hi\n"
        assert "permissions_unset" not in rules(content)

    def test_privileged_triggers_are_flagged(self) -> None:
        content = (
            "on: [pull_request_target]\npermissions: {contents: read}\n"
            "jobs:\n  b:\n    steps:\n      - run: echo hi\n"
        )
        assert "privileged_trigger" in rules(content)


class TestRobustness:
    def test_malformed_yaml_is_reported_not_raised(self) -> None:
        issues = analyse_workflow(PATH, "on: push\n  bad: [indent")
        assert issues and issues[0].rule == "unparseable"

    def test_an_empty_workflow_produces_nothing(self) -> None:
        assert analyse_workflow(PATH, "") == []

    def test_issue_ids_are_stable_across_runs(self) -> None:
        """Repeated polling must update the timeline, not duplicate it."""
        content = "on: push\npermissions: write-all\njobs:\n  b:\n    steps:\n      - run: echo hi\n"
        first = {i.external_id for i in analyse_workflow(PATH, content)}
        second = {i.external_id for i in analyse_workflow(PATH, content)}
        assert first == second and first


class TestMonitorResult:
    """An empty finding list must never be conflated with a failed analysis."""

    def test_a_clean_repository_reports_success(self) -> None:
        result = CiMonitorResult(repository="o/r", workflows_examined=4, runs_examined=10)
        assert result.reached_github is True

    def test_a_failed_analysis_is_distinguishable_from_a_clean_one(self) -> None:
        result = CiMonitorResult(repository="o/r", errors=["403 rate limit exceeded"])
        assert result.reached_github is False
        assert result.findings == []


@pytest.mark.parametrize(
    "trigger", ["pull_request_target", "workflow_run"]
)
def test_every_dangerous_trigger_is_recognised(trigger: str) -> None:
    content = (
        f"on: [{trigger}]\npermissions: {{contents: read}}\n"
        "jobs:\n  b:\n    steps:\n      - run: echo hi\n"
    )
    assert "privileged_trigger" in rules(content)
