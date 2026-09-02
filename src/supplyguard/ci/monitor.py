"""CI/CD pipeline integrity monitoring for GitHub Actions.

Produces a chronological event feed per repository rather than a single score,
because build-integrity problems are things that *happened*: a workflow gained
permissions on Tuesday, an action was repointed on Thursday. A score collapses
that into a number and loses the sequence, which is the part an incident
responder actually needs.

Two sources of evidence:

* **Workflow definitions** — static analysis of what the pipeline is allowed to
  do (see :mod:`supplyguard.ci.workflow_analysis`).
* **Workflow runs and their commits** — what the pipeline actually did, and
  which changes accompanied it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from supplyguard.ci.workflow_analysis import WorkflowIssue, analyse_workflow
from supplyguard.clients.github import GitHubClient, RepositoryRef, WorkflowRun
from supplyguard.core.types import Severity
from supplyguard.ecosystems import adapter_for_manifest
from supplyguard.utils.concurrency import gather_bounded

logger = logging.getLogger(__name__)

_WORKFLOW_PATH_PREFIX = ".github/workflows/"


@dataclass(slots=True)
class CiFinding:
    """One entry in the repository's CI timeline."""

    external_id: str
    event_type: str
    severity: Severity
    title: str
    description: str
    remediation: str | None = None
    repository: str | None = None
    workflow_name: str | None = None
    workflow_path: str | None = None
    commit_sha: str | None = None
    actor: str | None = None
    html_url: str | None = None
    occurred_at: datetime | None = None
    evidence: list[dict[str, Any]] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class CiMonitorResult:
    repository: str
    findings: list[CiFinding] = field(default_factory=list)
    runs_examined: int = 0
    workflows_examined: int = 0
    notes: list[str] = field(default_factory=list)


class CiMonitor:
    def __init__(self, client: GitHubClient) -> None:
        self.client = client

    async def analyse(
        self, ref: RepositoryRef, *, run_limit: int = 30, commit_limit: int = 15
    ) -> CiMonitorResult:
        result = CiMonitorResult(repository=ref.full_name)
        if not self.client.authenticated:
            result.notes.append(
                "No GitHub token configured. Unauthenticated API access is limited "
                "to 60 requests per hour and cannot read private repositories."
            )

        workflows = await self._safe(self.client.list_workflow_files(ref), {})
        result.workflows_examined = len(workflows)
        if not workflows:
            result.notes.append(
                "No workflow definitions were found under .github/workflows."
            )
        for path, content in workflows.items():
            for issue in analyse_workflow(path, content):
                result.findings.append(_from_workflow_issue(ref, issue))

        runs = await self._safe(self.client.list_workflow_runs(ref, limit=run_limit), [])
        result.runs_examined = len(runs)
        result.findings.extend(await self._analyse_commits(ref, runs, commit_limit))
        result.findings.extend(_analyse_run_patterns(ref, runs))

        result.findings.sort(
            key=lambda f: (f.occurred_at is None, -(f.occurred_at.timestamp() if f.occurred_at else 0))
        )
        return result

    async def _analyse_commits(
        self, ref: RepositoryRef, runs: list[WorkflowRun], limit: int
    ) -> list[CiFinding]:
        """Flag commits that change a workflow and a dependency manifest together.

        Changing how the build runs, in the same change that alters what the
        build installs, is the shape of an attempt to smuggle a malicious
        dependency past review alongside a plausible CI tweak. It is also
        completely normal in a routine "upgrade Node and bump deps" commit, so
        this is reported as something to look at, not as a confirmed attack.
        """
        seen: set[str] = set()
        shas: list[str] = []
        for run in runs:
            if run.head_sha and run.head_sha not in seen:
                seen.add(run.head_sha)
                shas.append(run.head_sha)
            if len(shas) >= limit:
                break
        if not shas:
            return []

        commits = await gather_bounded(
            [self.client.get_commit(ref, sha) for sha in shas], chunk=8
        )
        findings: list[CiFinding] = []
        for sha, commit in zip(shas, commits, strict=False):
            if not isinstance(commit, dict):
                continue
            paths = [f.get("filename", "") for f in commit.get("files") or []]
            workflow_paths = [p for p in paths if p.startswith(_WORKFLOW_PATH_PREFIX)]
            manifest_paths = [
                p for p in paths if adapter_for_manifest(p.rsplit("/", 1)[-1]) is not None
            ]
            if not (workflow_paths and manifest_paths):
                continue

            commit_info = commit.get("commit") or {}
            author = (commit.get("author") or {}).get("login") or (
                commit_info.get("author") or {}
            ).get("name")
            findings.append(
                CiFinding(
                    external_id=f"commit:{sha}:workflow_and_manifest",
                    event_type="workflow_and_manifest_changed_together",
                    severity=Severity.MEDIUM,
                    title=(
                        f"Commit {sha[:8]} changes both a workflow and a dependency manifest"
                    ),
                    description=(
                        "This commit modifies "
                        f"{', '.join(workflow_paths[:3])} and "
                        f"{', '.join(manifest_paths[:3])} together. Changing how the "
                        "build runs in the same change that alters what it installs "
                        "is how a malicious dependency gets reviewed as a build tweak. "
                        "Routine maintenance commits look identical, so this is a "
                        "prompt to read the diff rather than a finding on its own."
                    ),
                    remediation=(
                        "Review the workflow diff and the manifest diff separately. "
                        "Confirm that each added or changed dependency was intended, "
                        "and that the workflow change does not weaken permissions, "
                        "add a new registry, or introduce an unpinned action."
                    ),
                    repository=ref.full_name,
                    commit_sha=sha,
                    actor=author,
                    html_url=commit.get("html_url"),
                    occurred_at=_commit_time(commit_info),
                    evidence=[
                        {
                            "label": "Workflow files changed",
                            "detail": ", ".join(workflow_paths),
                            "weight": 0.5,
                        },
                        {
                            "label": "Manifests changed",
                            "detail": ", ".join(manifest_paths),
                            "weight": 0.5,
                        },
                        {
                            "label": "Commit message",
                            "detail": (commit_info.get("message") or "").split("\n")[0][:200],
                        },
                    ],
                    details={"workflows": workflow_paths, "manifests": manifest_paths},
                )
            )
        return findings

    @staticmethod
    async def _safe(awaitable, default):
        try:
            return await awaitable
        except Exception as exc:
            logger.warning("CI monitoring call failed: %s", exc)
            return default


def _analyse_run_patterns(ref: RepositoryRef, runs: list[WorkflowRun]) -> list[CiFinding]:
    """Flag re-run patterns worth a second look.

    A workflow that succeeds only on a later attempt is usually flakiness. It is
    also what a re-run looks like after someone changed something between
    attempts, so repeated retries on the same commit are surfaced — at low
    severity, because the benign explanation is far more common.
    """
    findings: list[CiFinding] = []
    for run in runs:
        if run.run_attempt >= 3 and run.conclusion == "success":
            findings.append(
                CiFinding(
                    external_id=f"run:{run.id}:repeated_attempts",
                    event_type="repeated_run_attempts",
                    severity=Severity.LOW,
                    title=f"Workflow '{run.name}' succeeded only on attempt {run.run_attempt}",
                    description=(
                        f"Run {run.id} on commit {run.head_sha[:8]} needed "
                        f"{run.run_attempt} attempts before succeeding. This is "
                        "usually flaky infrastructure, but a build that passes only "
                        "after repeated retries can also indicate that something "
                        "changed between attempts."
                    ),
                    remediation=(
                        "Compare the logs of the failed and successful attempts. If "
                        "the difference is not an infrastructure error, investigate "
                        "what changed between them."
                    ),
                    repository=ref.full_name,
                    workflow_name=run.name,
                    commit_sha=run.head_sha,
                    actor=run.actor,
                    html_url=run.html_url,
                    occurred_at=run.created_at,
                    evidence=[
                        {"label": "Attempts", "detail": str(run.run_attempt), "weight": 0.3},
                        {"label": "Trigger", "detail": run.event},
                        {"label": "Branch", "detail": run.head_branch or "unknown"},
                    ],
                    details={"run_id": run.id, "attempts": run.run_attempt},
                )
            )
    return findings


def _from_workflow_issue(ref: RepositoryRef, issue: WorkflowIssue) -> CiFinding:
    return CiFinding(
        external_id=issue.external_id,
        event_type=issue.rule,
        severity=issue.severity,
        title=issue.title,
        description=issue.description,
        remediation=issue.remediation,
        repository=ref.full_name,
        workflow_path=issue.workflow_path,
        workflow_name=issue.workflow_path.rsplit("/", 1)[-1],
        html_url=f"{ref.url}/blob/HEAD/{issue.workflow_path}",
        evidence=issue.evidence,
        details={**issue.details, "job": issue.job, "step": issue.step},
    )


def _commit_time(commit_info: dict) -> datetime | None:
    from supplyguard.utils.dates import parse_iso

    for key in ("committer", "author"):
        stamp = (commit_info.get(key) or {}).get("date")
        parsed = parse_iso(stamp)
        if parsed:
            return parsed
    return None
