"""Project CRUD and the dashboard's aggregate views."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import func, select

from supplyguard.api.deps import CurrentUser, OwnedProject, SessionDep
from supplyguard.api.schemas import (
    ProjectCreate,
    ProjectResponse,
    ProjectUpdate,
    RiskTrendPoint,
)
from supplyguard.db.models import Project, Scan

router = APIRouter(prefix="/projects", tags=["projects"])


@router.post("", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
async def create_project(
    payload: ProjectCreate, session: SessionDep, user: CurrentUser
) -> ProjectResponse:
    existing = await session.scalar(
        select(Project).where(Project.owner_id == user.id, Project.name == payload.name)
    )
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A project named {payload.name!r} already exists.",
        )
    project = Project(owner_id=user.id, **payload.model_dump())
    session.add(project)
    await session.flush()
    return ProjectResponse.model_validate(project)


@router.get("", response_model=list[ProjectResponse])
async def list_projects(session: SessionDep, user: CurrentUser) -> list[ProjectResponse]:
    """List projects with their latest risk score.

    The score comes from the most recent completed scan via one grouped query
    rather than a per-project lookup, so the dashboard stays a single round trip.
    """
    projects = (
        await session.scalars(
            select(Project).where(Project.owner_id == user.id).order_by(Project.created_at.desc())
        )
    ).all()
    if not projects:
        return []

    latest = (
        select(
            Scan.project_id,
            func.max(Scan.created_at).label("latest_at"),
            func.count(Scan.id).label("scan_count"),
        )
        .where(Scan.project_id.in_([p.id for p in projects]))
        .group_by(Scan.project_id)
        .subquery()
    )
    rows = (
        await session.execute(
            select(Scan.project_id, Scan.risk_score, Scan.risk_grade, latest.c.scan_count)
            .join(
                latest,
                (Scan.project_id == latest.c.project_id)
                & (Scan.created_at == latest.c.latest_at),
            )
        )
    ).all()
    by_project = {row[0]: row for row in rows}

    responses: list[ProjectResponse] = []
    for project in projects:
        response = ProjectResponse.model_validate(project)
        row = by_project.get(project.id)
        if row is not None:
            response.latest_risk_score = row[1]
            response.latest_risk_grade = row[2]
            response.scan_count = row[3]
        responses.append(response)
    return responses


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(project: OwnedProject, session: SessionDep) -> ProjectResponse:
    response = ProjectResponse.model_validate(project)
    latest = await session.scalar(
        select(Scan)
        .where(Scan.project_id == project.id, Scan.status == "completed")
        .order_by(Scan.created_at.desc())
        .limit(1)
    )
    if latest is not None:
        response.latest_risk_score = latest.risk_score
        response.latest_risk_grade = latest.risk_grade
    response.scan_count = (
        await session.scalar(
            select(func.count(Scan.id)).where(Scan.project_id == project.id)
        )
    ) or 0
    return response


@router.patch("/{project_id}", response_model=ProjectResponse)
async def update_project(
    payload: ProjectUpdate, project: OwnedProject, session: SessionDep
) -> ProjectResponse:
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(project, field, value)
    await session.flush()
    return ProjectResponse.model_validate(project)


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project(project: OwnedProject, session: SessionDep) -> None:
    await session.delete(project)


@router.get("/{project_id}/trend", response_model=list[RiskTrendPoint])
async def risk_trend(
    project: OwnedProject,
    session: SessionDep,
    limit: int = Query(default=30, ge=1, le=200),
) -> list[RiskTrendPoint]:
    """Risk score over time, oldest first, for the dashboard's trend chart."""
    scans = (
        await session.scalars(
            select(Scan)
            .where(Scan.project_id == project.id, Scan.status == "completed")
            .order_by(Scan.created_at.desc())
            .limit(limit)
        )
    ).all()
    return [
        RiskTrendPoint(
            scan_id=scan.id,
            created_at=scan.created_at,
            risk_score=scan.risk_score,
            risk_grade=scan.risk_grade,
            finding_count=scan.finding_count,
        )
        for scan in reversed(scans)
    ]
