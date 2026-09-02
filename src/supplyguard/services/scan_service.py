"""Running a scan and persisting the result.

Kept separate from both the HTTP layer and the worker so that the same code
path serves an API request, a queued job and a test.
"""

from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from supplyguard.clients.cache import build_cache
from supplyguard.clients.http import HttpClient
from supplyguard.config import get_settings
from supplyguard.core.scoring import finding_risk
from supplyguard.core.types import SEVERITY_ORDER, ScanStatus
from supplyguard.db.models import Dependency, Finding, Project, Scan
from supplyguard.detectors.base import DetectorConfig
from supplyguard.scanner import ScanRequest, ScanResult, Scanner
from supplyguard.utils.dates import utcnow

logger = logging.getLogger(__name__)


def detector_config_for(project: Project) -> DetectorConfig:
    """Build detector configuration from a project's stored overrides.

    Unknown keys are ignored rather than raising: a project configured against
    a newer schema must not make its own scans un-runnable.
    """
    config = DetectorConfig()
    overrides = project.settings or {}
    for field, value in overrides.items():
        if not hasattr(config, field):
            continue
        current = getattr(config, field)
        if isinstance(current, tuple) and isinstance(value, list):
            value = tuple(value)
        elif current is not None and not isinstance(value, type(current)):
            continue
        setattr(config, field, value)
    return config


async def run_and_persist_scan(
    session: AsyncSession,
    scan_id: str,
    files: dict[str, str],
    repository_url: str | None,
    ecosystems: list[str] | None = None,
    detectors: list[str] | None = None,
    github_token: str | None = None,
) -> Scan:
    """Execute a scan and write its results, updating the scan row's status."""
    scan = await session.get(Scan, scan_id)
    if scan is None:
        raise LookupError(f"Scan {scan_id} does not exist.")

    project = await session.get(Project, scan.project_id)
    scan.status = ScanStatus.RUNNING.value
    scan.started_at = utcnow()
    await session.flush()

    settings = get_settings()
    cache = await build_cache(settings.redis_url)
    http = HttpClient(
        cache=cache,
        timeout=settings.http_timeout_seconds,
        max_concurrency=settings.http_max_concurrency,
    )
    try:
        scanner = Scanner(http=http, github_token=github_token or settings.github_token)
        result = await scanner.scan(
            ScanRequest(
                files=files,
                repository_url=repository_url,
                ecosystems=ecosystems,
                detectors=detectors,
                config=detector_config_for(project) if project else DetectorConfig(),
                project_name=project.name if project else None,
            )
        )
    except Exception as exc:
        logger.exception("scan %s failed", scan_id)
        scan.status = ScanStatus.FAILED.value
        scan.error = str(exc)
        scan.finished_at = utcnow()
        await session.flush()
        return scan
    finally:
        await http.aclose()
        await cache.close()

    _persist(session, scan, result)
    await session.flush()
    return scan


def _persist(session: AsyncSession, scan: Scan, result: ScanResult) -> None:
    """Copy a ScanResult onto the scan row and its child tables."""
    scan.status = result.status.value
    scan.finished_at = result.finished_at or utcnow()
    scan.duration_seconds = result.duration_seconds
    scan.package_count = result.package_count
    scan.finding_count = len(result.findings)
    scan.error = "; ".join(result.errors) if result.errors else None

    if result.risk is not None:
        scan.risk_score = result.risk.score
        scan.risk_grade = result.risk.grade

    summary = result.summary()
    # The graphs are large; keep the per-scan JSON to what the dashboard needs.
    summary.pop("findings", None)
    scan.summary = summary

    for eco in result.ecosystems:
        for package in eco.graph.packages:
            session.add(
                Dependency(
                    scan_id=scan.id,
                    ecosystem=package.ecosystem,
                    name=package.name,
                    version=package.version,
                    depth=package.depth,
                    is_direct=package.is_direct,
                    is_dev=package.is_dev,
                    manifest_filename=eco.manifest_filename,
                    parents=list(package.parents),
                )
            )

    for finding in result.findings:
        session.add(
            Finding(
                scan_id=scan.id,
                category=finding.category.value,
                severity=finding.severity.value,
                severity_rank=SEVERITY_ORDER.index(finding.severity),
                title=finding.title,
                description=finding.description,
                detector=finding.detector,
                ecosystem=finding.ecosystem,
                package_name=finding.package_name,
                package_version=finding.package_version,
                identifier=finding.identifier,
                cvss_score=finding.cvss_score,
                affected_range=finding.affected_range,
                fixed_version=finding.fixed_version,
                remediation=finding.remediation,
                confidence=finding.confidence,
                depth=finding.depth,
                is_direct=finding.is_direct,
                risk_contribution=round(finding_risk(finding).risk, 3),
                references=list(finding.references),
                evidence=[
                    {"label": e.label, "detail": e.detail, "weight": e.weight}
                    for e in finding.evidence
                ],
                details=finding.metadata,
            )
        )


async def get_or_create_project(
    session: AsyncSession, owner_id: str, name: str, repository_url: str | None = None
) -> Project:
    project = await session.scalar(
        select(Project).where(Project.owner_id == owner_id, Project.name == name)
    )
    if project is None:
        project = Project(owner_id=owner_id, name=name, repository_url=repository_url)
        session.add(project)
        await session.flush()
    return project
