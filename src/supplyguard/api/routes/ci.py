"""CI/CD monitoring endpoints."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import select

from supplyguard.api.deps import CurrentUser, OwnedProject, SessionDep
from supplyguard.api.schemas import CiEventResponse, CiScanRequest
from supplyguard.ci.monitor import CiFinding, CiMonitor
from supplyguard.clients.cache import build_cache
from supplyguard.clients.github import GitHubClient, GitHubError, parse_repository_url
from supplyguard.clients.http import HttpClient
from supplyguard.config import get_settings
from supplyguard.db.models import CiEvent
from supplyguard.core.types import SEVERITY_ORDER, Severity

router = APIRouter(prefix="/projects/{project_id}/ci", tags=["ci"])


@router.post("/scan", response_model=list[CiEventResponse])
async def scan_ci(
    payload: CiScanRequest,
    project: OwnedProject,
    session: SessionDep,
    user: CurrentUser,
) -> list[CiEventResponse]:
    """Analyse a repository's GitHub Actions configuration and recent runs.

    Runs inline rather than through the queue: it is a handful of API calls
    against one repository, not a dependency-tree walk, and the caller wants
    the timeline back immediately.
    """
    repository_url = payload.repository_url or project.repository_url
    if not repository_url:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="This project has no repository_url; supply one in the request.",
        )
    try:
        ref = parse_repository_url(repository_url)
    except GitHubError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc

    settings = get_settings()
    cache = await build_cache(settings.redis_url)
    http = HttpClient(cache=cache, timeout=settings.http_timeout_seconds)
    try:
        token = user.github_access_token or settings.github_token
        monitor = CiMonitor(GitHubClient(http, token))
        result = await monitor.analyse(ref, run_limit=payload.run_limit)
    except GitHubError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
    finally:
        await http.aclose()
        await cache.close()

    stored = await _upsert_events(session, project.id, result.findings)
    return [CiEventResponse.model_validate(event) for event in stored]


@router.get("/events", response_model=list[CiEventResponse])
async def list_ci_events(
    project: OwnedProject,
    session: SessionDep,
    severity: str | None = Query(default=None),
    event_type: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
) -> list[CiEventResponse]:
    """The repository's CI timeline, newest first."""
    query = select(CiEvent).where(CiEvent.project_id == project.id)
    if severity:
        parsed = Severity.from_label(severity)
        if parsed is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Unknown severity {severity!r}.",
            )
        allowed = [s.value for s in SEVERITY_ORDER[: SEVERITY_ORDER.index(parsed) + 1]]
        query = query.where(CiEvent.severity.in_(allowed))
    if event_type:
        query = query.where(CiEvent.event_type == event_type)

    events = (
        await session.scalars(
            query.order_by(CiEvent.occurred_at.desc().nullslast(), CiEvent.id.desc()).limit(limit)
        )
    ).all()
    return [CiEventResponse.model_validate(event) for event in events]


@router.delete("/events", status_code=status.HTTP_204_NO_CONTENT)
async def clear_ci_events(project: OwnedProject, session: SessionDep) -> None:
    events = (
        await session.scalars(select(CiEvent).where(CiEvent.project_id == project.id))
    ).all()
    for event in events:
        await session.delete(event)


async def _upsert_events(
    session: SessionDep, project_id: str, findings: list[CiFinding]
) -> list[CiEvent]:
    """Insert new events, refresh existing ones.

    Keyed on `external_id` so that re-running the monitor updates the timeline
    in place rather than appending a duplicate of every standing issue.
    """
    if not findings:
        return []
    existing = {
        event.external_id: event
        for event in (
            await session.scalars(
                select(CiEvent).where(
                    CiEvent.project_id == project_id,
                    CiEvent.external_id.in_([f.external_id for f in findings]),
                )
            )
        ).all()
    }

    stored: list[CiEvent] = []
    for finding in findings:
        event = existing.get(finding.external_id)
        if event is None:
            event = CiEvent(project_id=project_id, external_id=finding.external_id)
            session.add(event)
        event.provider = "github"
        event.event_type = finding.event_type
        event.severity = finding.severity.value
        event.title = finding.title
        event.description = finding.description
        event.remediation = finding.remediation
        event.repository = finding.repository
        event.workflow_name = finding.workflow_name
        event.workflow_path = finding.workflow_path
        event.commit_sha = finding.commit_sha
        event.actor = finding.actor
        event.html_url = finding.html_url
        event.occurred_at = finding.occurred_at
        event.evidence = finding.evidence
        event.details = finding.details
        stored.append(event)

    await session.flush()
    return sorted(
        stored,
        key=lambda e: (SEVERITY_ORDER.index(Severity(e.severity)), e.title),
    )
