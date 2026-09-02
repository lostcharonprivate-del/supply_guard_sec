"""Scan orchestration.

Ties the two plugin layers together: route input files to ecosystem adapters,
parse them into dependency graphs, run every detector against each graph, then
deduplicate and score the results.

The orchestrator deliberately knows nothing about *how* any adapter parses or
any detector detects. Adding an ecosystem or a detector requires no change
here.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime

from supplyguard.clients.cache import Cache
from supplyguard.clients.github import GitHubClient, parse_repository_url
from supplyguard.clients.http import HttpClient
from supplyguard.core.scoring import RiskScore, score_findings
from supplyguard.core.types import SEVERITY_ORDER, DependencyGraph, Finding, ScanStatus
from supplyguard.detectors.base import (
    Detector,
    DetectorConfig,
    MetadataProvider,
    ScanContext,
    all_detectors,
    get_detector,
)
from supplyguard.ecosystems.base import (
    EcosystemAdapter,
    ManifestParseError,
    adapter_for_manifest,
    all_adapters,
)
from supplyguard.utils.dates import utcnow

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class ScanRequest:
    """What to scan. Either supply `files` directly or a `repository_url`."""

    files: dict[str, str] = field(default_factory=dict)
    repository_url: str | None = None
    #: Restrict to these ecosystems; None means every ecosystem detected.
    ecosystems: list[str] | None = None
    #: Restrict to these detectors by name; None means all of them.
    detectors: list[str] | None = None
    config: DetectorConfig = field(default_factory=DetectorConfig)
    project_name: str | None = None
    #: Skip everything requiring network access.
    offline: bool = False


@dataclass(slots=True)
class EcosystemResult:
    ecosystem: str
    manifest_filename: str
    graph: DependencyGraph
    package_count: int
    direct_count: int
    warnings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ScanResult:
    scan_id: str
    status: ScanStatus
    started_at: datetime
    finished_at: datetime | None = None
    duration_seconds: float = 0.0
    project_name: str | None = None
    repository_url: str | None = None
    ecosystems: list[EcosystemResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    risk: RiskScore | None = None
    notes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    detectors_run: list[str] = field(default_factory=list)
    http_stats: dict = field(default_factory=dict)

    @property
    def package_count(self) -> int:
        return sum(e.package_count for e in self.ecosystems)

    def summary(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "status": self.status.value,
            "project_name": self.project_name,
            "repository_url": self.repository_url,
            "duration_seconds": round(self.duration_seconds, 2),
            "package_count": self.package_count,
            "finding_count": len(self.findings),
            "ecosystems": [
                {
                    "ecosystem": e.ecosystem,
                    "manifest": e.manifest_filename,
                    "packages": e.package_count,
                    "direct": e.direct_count,
                }
                for e in self.ecosystems
            ],
            "risk": self.risk.as_dict() if self.risk else None,
            "detectors_run": self.detectors_run,
            "notes": self.notes,
            "errors": self.errors,
        }


class Scanner:
    """Runs a scan. One instance per scan; safe to reuse an HttpClient across many."""

    def __init__(
        self,
        http: HttpClient | None = None,
        *,
        cache: Cache | None = None,
        github_token: str | None = None,
    ) -> None:
        self._owns_http = http is None
        self.http = http or HttpClient(cache=cache)
        self.github_token = github_token

    async def aclose(self) -> None:
        if self._owns_http:
            await self.http.aclose()

    async def __aenter__(self) -> Scanner:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    # -- entry point --------------------------------------------------------
    async def scan(self, request: ScanRequest) -> ScanResult:
        started = time.perf_counter()
        result = ScanResult(
            scan_id=uuid.uuid4().hex[:16],
            status=ScanStatus.RUNNING,
            started_at=utcnow(),
            project_name=request.project_name,
            repository_url=request.repository_url,
        )

        try:
            files, registry_configs = await self._collect_inputs(request, result)
        except Exception as exc:
            result.status = ScanStatus.FAILED
            result.errors.append(str(exc))
            result.finished_at = utcnow()
            result.duration_seconds = time.perf_counter() - started
            return result

        grouped = self._route(files, request, result)
        if not grouped:
            result.notes.append(
                "No supported manifest or lockfile was found. Supported files: "
                + ", ".join(sorted(_supported_filenames()))
            )
            result.status = ScanStatus.COMPLETED
            result.finished_at = utcnow()
            result.duration_seconds = time.perf_counter() - started
            return result

        detectors = self._select_detectors(request, result)
        result.detectors_run = [d.name for d in detectors]

        all_findings: list[Finding] = []
        for adapter, graphs in grouped.items():
            for graph in graphs:
                result.ecosystems.append(
                    EcosystemResult(
                        ecosystem=adapter.name,
                        manifest_filename=graph.manifest_filename,
                        graph=graph,
                        package_count=len(graph),
                        direct_count=len(graph.direct),
                        warnings=list(graph.warnings),
                    )
                )
                result.notes.extend(
                    f"{graph.manifest_filename}: {w}" for w in graph.warnings
                )

                ctx = ScanContext(
                    adapter=adapter,
                    graph=graph,
                    http=self.http,
                    metadata=MetadataProvider(
                        adapter, self.http, budget=request.config.max_metadata_lookups
                    ),
                    config=request.config,
                    registry_configs=self._configs_for(adapter, registry_configs),
                    repository_url=request.repository_url,
                    github_token=self.github_token,
                )
                findings = await self._run_detectors(detectors, ctx, request)
                all_findings.extend(findings)
                result.notes.extend(ctx.notes)

        result.findings = _dedupe_and_sort(all_findings)
        result.risk = score_findings(result.findings)
        result.status = ScanStatus.COMPLETED
        result.finished_at = utcnow()
        result.duration_seconds = time.perf_counter() - started
        result.http_stats = self.http.stats.as_dict()
        return result

    # -- inputs -------------------------------------------------------------
    async def _collect_inputs(
        self, request: ScanRequest, result: ScanResult
    ) -> tuple[dict[str, str], dict[str, str]]:
        files = dict(request.files)
        registry_configs: dict[str, str] = {}

        if request.repository_url:
            if request.offline:
                raise ValueError("Cannot scan a repository URL in offline mode.")
            ref = parse_repository_url(request.repository_url)
            client = GitHubClient(self.http, self.github_token)
            if not client.authenticated:
                result.notes.append(
                    "No GitHub token configured: the API allows only 60 requests "
                    "per hour unauthenticated, which a large repository can exhaust."
                )
            fetched = await client.fetch_manifests(ref)
            files.update(fetched.manifests)
            registry_configs.update(fetched.registry_configs)
            result.notes.extend(fetched.notes)
            result.project_name = result.project_name or ref.full_name
            result.repository_url = ref.url

        # Separate registry configs supplied directly in `files`.
        config_names = {
            pattern
            for adapter in all_adapters()
            for pattern in adapter.registry_config_patterns
        }
        for name in list(files):
            base = name.rsplit("/", 1)[-1]
            if base in config_names and not adapter_for_manifest(base):
                registry_configs[name] = files.pop(name)
            elif base in config_names:
                # Gemfile is both a manifest and a config source.
                registry_configs[name] = files[name]
        return files, registry_configs

    def _configs_for(
        self, adapter: EcosystemAdapter, registry_configs: dict[str, str]
    ) -> dict[str, str]:
        wanted = set(adapter.registry_config_patterns)
        return {
            name: content
            for name, content in registry_configs.items()
            if name.rsplit("/", 1)[-1] in wanted
        }

    # -- routing ------------------------------------------------------------
    def _route(
        self, files: dict[str, str], request: ScanRequest, result: ScanResult
    ) -> dict[EcosystemAdapter, list[DependencyGraph]]:
        """Map each file onto an adapter and parse it."""
        allowed = {e.lower() for e in request.ecosystems} if request.ecosystems else None
        grouped: dict[EcosystemAdapter, list[DependencyGraph]] = {}
        parsed_by_ecosystem: dict[str, list[tuple[str, DependencyGraph]]] = {}

        for filename, content in sorted(files.items()):
            adapter = adapter_for_manifest(filename)
            if adapter is None:
                continue
            if allowed is not None and adapter.name not in allowed:
                continue
            try:
                graph = adapter.parse_manifest(content, filename)
            except ManifestParseError as exc:
                result.errors.append(f"{filename}: {exc}")
                continue
            except Exception as exc:  # a malformed file must not kill the scan
                logger.exception("failed to parse %s", filename)
                result.errors.append(f"{filename}: unexpected parse failure: {exc}")
                continue
            if not len(graph):
                result.notes.append(f"{filename}: no dependencies found.")
                continue
            parsed_by_ecosystem.setdefault(adapter.name, []).append((filename, graph))
            grouped.setdefault(adapter, []).append(graph)

        # When both a lockfile and its loose manifest are present, the lockfile
        # is authoritative: keeping both would double-report every package and
        # inflate the risk score.
        for adapter, graphs in list(grouped.items()):
            lockfiles = [g for g in graphs if adapter.is_lockfile(g.manifest_filename)]
            if lockfiles and len(lockfiles) < len(graphs):
                dropped = [
                    g.manifest_filename for g in graphs if g not in lockfiles
                ]
                result.notes.append(
                    f"Ignored {', '.join(dropped)} because a resolved lockfile "
                    f"({', '.join(g.manifest_filename for g in lockfiles)}) was also provided."
                )
                grouped[adapter] = lockfiles
        return grouped

    # -- detectors ----------------------------------------------------------
    def _select_detectors(self, request: ScanRequest, result: ScanResult) -> list[Detector]:
        if request.detectors:
            selected: list[Detector] = []
            for name in request.detectors:
                try:
                    selected.append(get_detector(name))
                except KeyError as exc:
                    result.errors.append(str(exc))
            detectors = selected
        else:
            detectors = all_detectors()

        if request.offline:
            skipped = [d.name for d in detectors if d.requires_network]
            detectors = [d for d in detectors if not d.requires_network]
            if skipped:
                result.notes.append(
                    "Offline mode: skipped network-dependent detectors "
                    f"({', '.join(sorted(skipped))})."
                )
        return detectors

    async def _run_detectors(
        self, detectors: list[Detector], ctx: ScanContext, request: ScanRequest
    ) -> list[Finding]:
        """Run detectors concurrently against one dependency graph.

        `safe_detect` contains failures per detector, so a registry outage
        during malicious-package heuristics still leaves the CVE results intact.
        """
        results = await asyncio.gather(
            *(detector.safe_detect(ctx) for detector in detectors),
            return_exceptions=True,
        )
        findings: list[Finding] = []
        for detector, outcome in zip(detectors, results, strict=False):
            if isinstance(outcome, BaseException):
                logger.exception("detector %s raised", detector.name, exc_info=outcome)
                ctx.notes.append(f"Detector '{detector.name}' failed: {outcome}")
                continue
            findings.extend(outcome)
        return findings


def _dedupe_and_sort(findings: list[Finding]) -> list[Finding]:
    """Collapse duplicates, then order by what a reader should act on first."""
    best: dict[str, Finding] = {}
    for finding in findings:
        key = finding.dedupe_key
        current = best.get(key)
        if current is None or _rank(finding) < _rank(current):
            best[key] = finding
    return sorted(best.values(), key=_rank)


def _rank(finding: Finding) -> tuple:
    return (
        SEVERITY_ORDER.index(finding.severity),
        0 if finding.is_direct else 1,
        -finding.confidence,
        finding.depth,
        finding.package_name or "",
        finding.identifier or finding.title,
    )


def _supported_filenames() -> set[str]:
    return {
        pattern
        for adapter in all_adapters()
        for pattern in adapter.manifest_patterns
    }
