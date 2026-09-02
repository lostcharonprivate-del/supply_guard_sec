"""GitHub API client.

Serves three jobs:

* fetching manifests from a repository URL, so a scan can start from a repo
  rather than an upload;
* reading workflow definitions and runs for CI/CD integrity monitoring;
* querying the GitHub Advisory Database via GraphQL to cross-check OSV.

An unauthenticated client works but is rate-limited to 60 requests/hour, which
one repository scan can exhaust. A token raises that to 5,000/hour and is
required for the GraphQL endpoint.
"""

from __future__ import annotations

import base64
import binascii
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from supplyguard.clients.http import HttpClient
from supplyguard.utils.dates import parse_iso

logger = logging.getLogger(__name__)

API = "https://api.github.com"
GRAPHQL = "https://api.github.com/graphql"

#: Files worth pulling from a repository for a scan.
_MANIFEST_NAMES = {
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "package.json",
    "requirements.txt", "poetry.lock", "uv.lock", "Pipfile.lock", "pyproject.toml",
    "Gemfile.lock", "gems.locked", "Gemfile",
    "pom.xml", "gradle.lockfile",
}
_CONFIG_NAMES = {
    ".npmrc", ".yarnrc", ".yarnrc.yml", "pip.conf", "pip.ini", ".gemrc", "settings.xml",
}
_MANIFEST_PATTERNS = (re.compile(r"^requirements[\w.-]*\.txt$"), re.compile(r"^[\w.-]*\.gradle\.lockfile$"))

#: Directories that only ever contain fixtures, examples or vendored copies.
_IGNORED_PATH_SEGMENTS = (
    "node_modules/", "/test/fixtures/", "/tests/fixtures/", "/__fixtures__/",
    "/vendor/", "/.git/", "/site-packages/",
)


class GitHubError(RuntimeError):
    pass


@dataclass(slots=True)
class RepositoryRef:
    owner: str
    repo: str
    ref: str | None = None

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.repo}"

    @property
    def url(self) -> str:
        return f"https://github.com/{self.full_name}"


@dataclass(slots=True)
class RepositoryFiles:
    repository: RepositoryRef
    default_branch: str
    manifests: dict[str, str] = field(default_factory=dict)
    registry_configs: dict[str, str] = field(default_factory=dict)
    truncated: bool = False
    notes: list[str] = field(default_factory=list)


@dataclass(slots=True)
class WorkflowRun:
    id: int
    name: str
    display_title: str
    event: str
    status: str
    conclusion: str | None
    head_branch: str | None
    head_sha: str
    actor: str | None
    created_at: datetime | None
    html_url: str
    run_attempt: int = 1


def parse_repository_url(url: str) -> RepositoryRef:
    """Accept the many shapes a GitHub repo reference arrives in."""
    text = url.strip().rstrip("/")
    text = re.sub(r"\.git$", "", text)
    patterns = (
        r"^(?:https?://)?(?:www\.)?github\.com/(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+)"
        r"(?:/tree/(?P<ref>[\w./-]+))?",
        r"^git@github\.com:(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+)$",
        r"^(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+)$",
    )
    for pattern in patterns:
        match = re.match(pattern, text)
        if match:
            groups = match.groupdict()
            return RepositoryRef(groups["owner"], groups["repo"], groups.get("ref"))
    raise GitHubError(
        f"Could not parse {url!r} as a GitHub repository. Expected something like "
        "https://github.com/owner/repo or owner/repo."
    )


class GitHubClient:
    def __init__(self, http: HttpClient, token: str | None = None) -> None:
        self.http = http
        self.token = token
        self._headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if token:
            self._headers["Authorization"] = f"Bearer {token}"

    @property
    def authenticated(self) -> bool:
        return bool(self.token)

    async def _get(self, path: str, *, ttl: int = 3600, **kwargs: Any) -> Any:
        url = path if path.startswith("http") else f"{API}{path}"
        return await self.http.get_json(url, headers=self._headers, ttl=ttl, **kwargs)

    # -- repository ---------------------------------------------------------
    async def get_repository(self, ref: RepositoryRef) -> dict | None:
        return await self._get(f"/repos/{ref.owner}/{ref.repo}", ttl=3600)

    async def fetch_manifests(self, ref: RepositoryRef, *, max_files: int = 40) -> RepositoryFiles:
        """Locate and download every manifest and registry config in a repo.

        Uses the git tree API rather than cloning: one request enumerates the
        whole repository, and only the handful of files that matter are then
        downloaded.
        """
        repository = await self.get_repository(ref)
        if repository is None:
            raise GitHubError(
                f"Repository {ref.full_name} was not found, or is private and this "
                "token cannot see it."
            )
        default_branch = repository.get("default_branch") or "main"
        target = ref.ref or default_branch

        result = RepositoryFiles(repository=ref, default_branch=default_branch)

        tree = await self._get(
            f"/repos/{ref.owner}/{ref.repo}/git/trees/{target}",
            params={"recursive": "1"},
            ttl=1800,
        )
        if tree is None:
            raise GitHubError(f"Could not read the file tree of {ref.full_name} at {target!r}.")
        if tree.get("truncated"):
            result.truncated = True
            result.notes.append(
                "The repository tree is too large for the GitHub API to return in "
                "full, so some manifests may not have been discovered."
            )

        candidates: list[str] = []
        for entry in tree.get("tree") or []:
            if entry.get("type") != "blob":
                continue
            path = entry.get("path") or ""
            if _is_ignored(path):
                continue
            if _is_interesting(path.rsplit("/", 1)[-1]):
                candidates.append(path)

        # Prefer shallow paths: the root manifest is the project's real one.
        candidates.sort(key=lambda p: (p.count("/"), len(p)))
        if len(candidates) > max_files:
            result.notes.append(
                f"Found {len(candidates)} manifest files; scanning the {max_files} "
                "closest to the repository root."
            )
            candidates = candidates[:max_files]

        contents = await self.http.gather(
            [self._get_file(ref, target, path) for path in candidates]
        )
        for path, content in zip(candidates, contents, strict=False):
            if not isinstance(content, str):
                continue
            base = path.rsplit("/", 1)[-1]
            if base in _CONFIG_NAMES:
                result.registry_configs[path] = content
            else:
                result.manifests[path] = content

        if not result.manifests:
            result.notes.append(
                "No supported manifest or lockfile was found in this repository."
            )
        return result

    async def _get_file(self, ref: RepositoryRef, target: str, path: str) -> str | None:
        try:
            data = await self._get(
                f"/repos/{ref.owner}/{ref.repo}/contents/{path}",
                params={"ref": target},
                ttl=1800,
            )
        except Exception as exc:
            logger.warning("could not fetch %s from %s: %s", path, ref.full_name, exc)
            return None
        if not isinstance(data, dict):
            return None
        if data.get("encoding") == "base64" and data.get("content"):
            try:
                return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
            except (binascii.Error, ValueError):
                return None
        content = data.get("content")
        return content if isinstance(content, str) else None

    # -- CI/CD --------------------------------------------------------------
    async def list_workflow_files(self, ref: RepositoryRef) -> dict[str, str]:
        """Fetch every workflow definition under .github/workflows."""
        try:
            entries = await self._get(
                f"/repos/{ref.owner}/{ref.repo}/contents/.github/workflows", ttl=1800
            )
        except Exception:
            return {}
        if not isinstance(entries, list):
            return {}
        paths = [
            e["path"]
            for e in entries
            if e.get("type") == "file" and str(e.get("name", "")).endswith((".yml", ".yaml"))
        ]
        target = ref.ref or "HEAD"
        contents = await self.http.gather([self._get_file(ref, target, p) for p in paths])
        return {
            path: content
            for path, content in zip(paths, contents, strict=False)
            if isinstance(content, str)
        }

    async def list_workflow_runs(
        self, ref: RepositoryRef, *, limit: int = 50
    ) -> list[WorkflowRun]:
        data = await self._get(
            f"/repos/{ref.owner}/{ref.repo}/actions/runs",
            params={"per_page": str(min(limit, 100))},
            ttl=300,
        )
        runs: list[WorkflowRun] = []
        for entry in (data or {}).get("workflow_runs") or []:
            runs.append(
                WorkflowRun(
                    id=entry["id"],
                    name=entry.get("name") or "",
                    display_title=entry.get("display_title") or "",
                    event=entry.get("event") or "",
                    status=entry.get("status") or "",
                    conclusion=entry.get("conclusion"),
                    head_branch=entry.get("head_branch"),
                    head_sha=entry.get("head_sha") or "",
                    actor=(entry.get("actor") or {}).get("login"),
                    created_at=parse_iso(entry.get("created_at")),
                    html_url=entry.get("html_url") or "",
                    run_attempt=entry.get("run_attempt") or 1,
                )
            )
        return runs

    async def get_commit(self, ref: RepositoryRef, sha: str) -> dict | None:
        return await self._get(f"/repos/{ref.owner}/{ref.repo}/commits/{sha}", ttl=86_400)

    async def list_pull_request_files(self, ref: RepositoryRef, number: int) -> list[dict]:
        data = await self._get(
            f"/repos/{ref.owner}/{ref.repo}/pulls/{number}/files",
            params={"per_page": "100"},
            ttl=3600,
        )
        return data if isinstance(data, list) else []

    async def get_action_repository(self, owner: str, repo: str) -> dict | None:
        """Metadata for a third-party Action's repository (stars, archived, age)."""
        try:
            return await self._get(f"/repos/{owner}/{repo}", ttl=86_400)
        except Exception:
            return None

    # -- advisories ---------------------------------------------------------
    async def query_advisories(self, ecosystem: str, package: str) -> list[dict]:
        """Cross-check a package against the GitHub Advisory Database.

        OSV already ingests GHSA data, so this is a corroboration path rather
        than a primary source — useful for CVE metadata OSV has not picked up
        yet. Requires a token; returns an empty list without one.
        """
        if not self.token:
            return []
        query = """
        query($ecosystem: SecurityAdvisoryEcosystem!, $package: String!) {
          securityVulnerabilities(ecosystem: $ecosystem, package: $package, first: 50) {
            nodes {
              severity
              vulnerableVersionRange
              firstPatchedVersion { identifier }
              advisory {
                ghsaId summary publishedAt withdrawnAt
                cvss { score vectorString }
                identifiers { type value }
                references { url }
              }
            }
          }
        }
        """
        try:
            response = await self.http.post_json(
                GRAPHQL,
                {"query": query, "variables": {"ecosystem": ecosystem, "package": package}},
                headers=self._headers,
                ttl=21_600,
            )
        except Exception as exc:
            logger.warning("GitHub advisory query failed for %s: %s", package, exc)
            return []
        if not response or "errors" in response:
            return []
        return (
            ((response.get("data") or {}).get("securityVulnerabilities") or {}).get("nodes")
            or []
        )

    async def rate_limit(self) -> dict | None:
        return await self._get("/rate_limit", ttl=0)


def _is_interesting(basename: str) -> bool:
    if basename in _MANIFEST_NAMES or basename in _CONFIG_NAMES:
        return True
    return any(pattern.match(basename) for pattern in _MANIFEST_PATTERNS)


def _is_ignored(path: str) -> bool:
    padded = f"/{path}"
    return any(segment in padded for segment in _IGNORED_PATH_SEGMENTS)
