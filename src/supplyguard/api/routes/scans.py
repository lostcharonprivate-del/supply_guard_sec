"""Scan submission, polling and results."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, UploadFile, status
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from supplyguard.api.deps import CurrentUser, SessionDep, get_owned_project
from supplyguard.api.schemas import (
    DependencyResponse,
    DependencyTreeNode,
    FindingResponse,
    ScanAccepted,
    ScanCreate,
    ScanDetailResponse,
    ScanResponse,
)
from supplyguard.config import get_settings
from supplyguard.core.types import SEVERITY_ORDER, ScanStatus, Severity
from supplyguard.db.models import Dependency, Finding, Project, Scan
from supplyguard.jobs.queue import enqueue_scan
from supplyguard.services.scan_service import get_or_create_project

router = APIRouter(tags=["scans"])


@router.post("/scans", response_model=ScanAccepted, status_code=status.HTTP_202_ACCEPTED)
async def create_scan(
    payload: ScanCreate, session: SessionDep, user: CurrentUser
) -> ScanAccepted:
    """Submit a scan.

    Returns immediately with a scan id: the work runs in the background because
    a full dependency tree against several external APIs takes far longer than
    a request should.
    """
    if not payload.files and not payload.repository_url:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Provide `files` or a `repository_url`.",
        )

    if payload.project_id:
        project = await get_owned_project(payload.project_id, session, user)
    else:
        name = payload.project_name or payload.repository_url or "Untitled project"
        project = await get_or_create_project(
            session, user.id, name, repository_url=payload.repository_url
        )

    scan = Scan(project_id=project.id, status=ScanStatus.QUEUED.value)
    session.add(scan)
    await session.flush()
    scan_id = scan.id
    # The row must be visible to the worker before the job is picked up.
    await session.commit()

    await enqueue_scan(
        scan_id=scan_id,
        files=payload.files,
        repository_url=payload.repository_url,
        ecosystems=payload.ecosystems,
        detectors=payload.detectors,
        github_token=user.github_access_token,
    )
    prefix = get_settings().api_prefix
    return ScanAccepted(
        scan_id=scan_id,
        project_id=project.id,
        status=ScanStatus.QUEUED.value,
        poll_url=f"{prefix}/scans/{scan_id}",
    )


@router.post("/scans/upload", response_model=ScanAccepted, status_code=status.HTTP_202_ACCEPTED)
async def create_scan_from_upload(
    session: SessionDep,
    user: CurrentUser,
    files: list[UploadFile],
    project_name: str | None = Query(default=None),
) -> ScanAccepted:
    """Submit a scan from multipart file uploads."""
    settings = get_settings()
    if len(files) > settings.max_files_per_scan:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"At most {settings.max_files_per_scan} files may be uploaded.",
        )

    contents: dict[str, str] = {}
    total = 0
    for upload in files:
        raw = await upload.read()
        total += len(raw)
        if total > settings.max_upload_bytes:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Uploads exceed {settings.max_upload_bytes // (1024 * 1024)}MB.",
            )
        contents[upload.filename or "unnamed"] = raw.decode("utf-8", errors="replace")

    return await create_scan(
        ScanCreate(files=contents, project_name=project_name), session, user
    )


@router.get("/scans/{scan_id}", response_model=ScanDetailResponse)
async def get_scan(
    scan_id: str,
    session: SessionDep,
    user: CurrentUser,
    severity: str | None = Query(default=None, description="Minimum severity."),
    category: str | None = Query(default=None),
    include_findings: bool = Query(default=True),
) -> ScanDetailResponse:
    scan = await _owned_scan(session, scan_id, user.id)
    # Validate against the base model, which has no relationship fields:
    # letting pydantic read `scan.findings` off the ORM object would trigger a
    # lazy load, and a lazy load inside async SQLAlchemy raises MissingGreenlet.
    response = ScanDetailResponse(**ScanResponse.model_validate(scan).model_dump())
    if not include_findings:
        return response

    query = select(Finding).where(Finding.scan_id == scan.id)
    if severity:
        parsed = Severity.from_label(severity)
        if parsed is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Unknown severity {severity!r}.",
            )
        query = query.where(Finding.severity_rank <= SEVERITY_ORDER.index(parsed))
    if category:
        query = query.where(Finding.category == category)

    findings = (
        await session.scalars(
            query.order_by(
                Finding.severity_rank, Finding.is_direct.desc(), Finding.risk_contribution.desc()
            )
        )
    ).all()
    response.findings = [FindingResponse.model_validate(f) for f in findings]
    return response


@router.get("/scans/{scan_id}/dependencies", response_model=list[DependencyResponse])
async def list_dependencies(
    scan_id: str,
    session: SessionDep,
    user: CurrentUser,
    direct_only: bool = Query(default=False),
) -> list[DependencyResponse]:
    scan = await _owned_scan(session, scan_id, user.id)
    query = select(Dependency).where(Dependency.scan_id == scan.id)
    if direct_only:
        query = query.where(Dependency.is_direct.is_(True))
    rows = (await session.scalars(query.order_by(Dependency.depth, Dependency.name))).all()
    return [DependencyResponse.model_validate(row) for row in rows]


@router.get("/scans/{scan_id}/tree", response_model=list[DependencyTreeNode])
async def dependency_tree(
    scan_id: str,
    session: SessionDep,
    user: CurrentUser,
    max_depth: int = Query(default=4, ge=1, le=10),
) -> list[DependencyTreeNode]:
    """The dependency tree with findings overlaid, for the visualisation.

    Built from the stored parent links. Depth is capped and each node is
    expanded once, because a real npm tree contains cycles through dev
    dependencies and would otherwise not terminate.
    """
    scan = await _owned_scan(session, scan_id, user.id)
    dependencies = (
        await session.scalars(select(Dependency).where(Dependency.scan_id == scan.id))
    ).all()
    findings = (
        await session.scalars(
            select(Finding).where(Finding.scan_id == scan.id, Finding.package_name.isnot(None))
        )
    ).all()

    worst: dict[str, tuple[int, str]] = {}
    counts: dict[str, int] = {}
    for finding in findings:
        name = finding.package_name or ""
        counts[name] = counts.get(name, 0) + 1
        current = worst.get(name)
        if current is None or finding.severity_rank < current[0]:
            worst[name] = (finding.severity_rank, finding.severity)

    by_key = {f"{d.name}@{d.version}": d for d in dependencies}
    children: dict[str, list[str]] = {}
    for dependency in dependencies:
        for parent in dependency.parents or []:
            children.setdefault(parent, []).append(f"{dependency.name}@{dependency.version}")

    def build(key: str, depth: int, seen: frozenset[str]) -> DependencyTreeNode | None:
        dependency = by_key.get(key)
        if dependency is None:
            return None
        node = DependencyTreeNode(
            key=key,
            name=dependency.name,
            version=dependency.version,
            ecosystem=dependency.ecosystem,
            depth=dependency.depth,
            is_direct=dependency.is_direct,
            is_dev=dependency.is_dev,
            severity=worst.get(dependency.name, (None, None))[1],
            finding_count=counts.get(dependency.name, 0),
        )
        if depth < max_depth and key not in seen:
            nested = seen | {key}
            for child_key in sorted(set(children.get(key, []))):
                child = build(child_key, depth + 1, nested)
                if child is not None:
                    node.children.append(child)
        return node

    roots = [d for d in dependencies if d.is_direct]
    tree: list[DependencyTreeNode] = []
    for root in sorted(roots, key=lambda d: d.name):
        node = build(f"{root.name}@{root.version}", 0, frozenset())
        if node is not None:
            tree.append(node)
    return tree


@router.get("/projects/{project_id}/scans", response_model=list[ScanResponse])
async def list_project_scans(
    project_id: str,
    session: SessionDep,
    user: CurrentUser,
    limit: int = Query(default=20, ge=1, le=100),
) -> list[ScanResponse]:
    project = await get_owned_project(project_id, session, user)
    scans = (
        await session.scalars(
            select(Scan)
            .where(Scan.project_id == project.id)
            .order_by(Scan.created_at.desc())
            .limit(limit)
        )
    ).all()
    return [ScanResponse.model_validate(scan) for scan in scans]


@router.delete("/scans/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(scan_id: str, session: SessionDep, user: CurrentUser) -> None:
    scan = await _owned_scan(session, scan_id, user.id)
    await session.delete(scan)


async def _owned_scan(session: SessionDep, scan_id: str, user_id: str) -> Scan:
    scan = await session.scalar(
        select(Scan)
        .join(Project, Project.id == Scan.project_id)
        .where(Scan.id == scan_id, Project.owner_id == user_id)
        .options(selectinload(Scan.project))
    )
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
    return scan
