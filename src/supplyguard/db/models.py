"""Database schema.

Findings are stored in one polymorphic table discriminated by `category`,
rather than one table per detector. That is deliberate: the dashboard's primary
view is "everything wrong with this project, worst first", which a single table
answers with one indexed query. Category-specific data lives in a JSONB column
that each detector owns.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

#: JSONB on Postgres, plain JSON elsewhere so the test-suite can use SQLite.
JSONType = JSON().with_variant(JSONB(), "postgresql")


class Base(DeclarativeBase):
    pass


def _uuid() -> str:
    return uuid.uuid4().hex


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str | None] = mapped_column(String(255))
    display_name: Mapped[str | None] = mapped_column(String(120))
    #: Set when the account was created through GitHub OAuth.
    github_login: Mapped[str | None] = mapped_column(String(120), unique=True)
    github_access_token: Mapped[str | None] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    projects: Mapped[list[Project]] = relationship(
        back_populates="owner", cascade="all, delete-orphan"
    )


class Project(Base, TimestampMixin):
    __tablename__ = "projects"
    __table_args__ = (UniqueConstraint("owner_id", "name", name="uq_project_owner_name"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    owner_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    repository_url: Mapped[str | None] = mapped_column(String(500))
    #: Detector configuration overrides for this project, e.g. organisation
    #: scopes that the dependency-confusion detector should treat as private.
    settings: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)

    owner: Mapped[User] = relationship(back_populates="projects")
    scans: Mapped[list[Scan]] = relationship(
        back_populates="project", cascade="all, delete-orphan", order_by="Scan.created_at.desc()"
    )
    ci_events: Mapped[list[CiEvent]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )


class Scan(Base, TimestampMixin):
    __tablename__ = "scans"
    __table_args__ = (
        Index("ix_scans_project_created", "project_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True, nullable=False
    )
    status: Mapped[str] = mapped_column(String(20), default="queued", nullable=False, index=True)
    #: 0-100, higher is worse. Kept on the scan row so the trend chart is a
    #: single indexed query rather than a re-aggregation of every finding.
    risk_score: Mapped[float | None] = mapped_column(Float)
    risk_grade: Mapped[str | None] = mapped_column(String(2))
    package_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    finding_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    duration_seconds: Mapped[float | None] = mapped_column(Float)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(Text)
    #: Manifest filenames, ecosystem summary, notes, detector list, score breakdown.
    summary: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)

    project: Mapped[Project] = relationship(back_populates="scans")
    dependencies: Mapped[list[Dependency]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    findings: Mapped[list[Finding]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class Dependency(Base):
    __tablename__ = "dependencies"
    __table_args__ = (
        Index("ix_dependencies_scan_name", "scan_id", "name"),
        UniqueConstraint("scan_id", "ecosystem", "name", "version", name="uq_dependency_identity"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=False
    )
    ecosystem: Mapped[str] = mapped_column(String(32), nullable=False)
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    version: Mapped[str] = mapped_column(String(120), nullable=False)
    depth: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    is_direct: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_dev: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    manifest_filename: Mapped[str | None] = mapped_column(String(300))
    #: Parent `name@version` keys, for rendering the tree.
    parents: Mapped[list[str]] = mapped_column(JSONType, default=list)

    scan: Mapped[Scan] = relationship(back_populates="dependencies")


class Finding(Base):
    """One finding from any detector.

    `category` is the discriminator; `details` carries whatever that category
    needs (imitation target for a typosquat, CVSS vector for a CVE) without
    forcing a schema migration every time a detector learns something new.
    """

    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_scan_severity", "scan_id", "severity"),
        Index("ix_findings_scan_category", "scan_id", "category"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=False
    )
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    #: Ordinal rank of the severity, so ORDER BY works without a CASE expression.
    severity_rank: Mapped[int] = mapped_column(Integer, nullable=False, default=99)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    detector: Mapped[str] = mapped_column(String(64), default="")

    ecosystem: Mapped[str | None] = mapped_column(String(32))
    package_name: Mapped[str | None] = mapped_column(String(300), index=True)
    package_version: Mapped[str | None] = mapped_column(String(120))
    identifier: Mapped[str | None] = mapped_column(String(120), index=True)

    cvss_score: Mapped[float | None] = mapped_column(Float)
    affected_range: Mapped[str | None] = mapped_column(String(200))
    fixed_version: Mapped[str | None] = mapped_column(String(120))
    remediation: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    depth: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    is_direct: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    #: This finding's contribution to the project risk score.
    risk_contribution: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    references: Mapped[list[str]] = mapped_column(JSONType, default=list)
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSONType, default=list)
    details: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)

    scan: Mapped[Scan] = relationship(back_populates="findings")


class CiEvent(Base):
    """A CI/CD observation, rendered as a per-repository timeline.

    Stored separately from `findings` because these are events in time rather
    than properties of a dependency tree: they accumulate across scans and are
    read chronologically.
    """

    __tablename__ = "ci_events"
    __table_args__ = (
        Index("ix_ci_events_project_occurred", "project_id", "occurred_at"),
        UniqueConstraint("project_id", "external_id", name="uq_ci_event_external"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True, nullable=False
    )
    #: Stable identity for the underlying object (workflow run id, commit sha
    #: plus rule), so repeated polling does not duplicate the timeline.
    external_id: Mapped[str] = mapped_column(String(200), nullable=False)
    provider: Mapped[str] = mapped_column(String(32), default="github", nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), default="info", nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str | None] = mapped_column(Text)

    repository: Mapped[str | None] = mapped_column(String(300))
    workflow_name: Mapped[str | None] = mapped_column(String(300))
    workflow_path: Mapped[str | None] = mapped_column(String(500))
    commit_sha: Mapped[str | None] = mapped_column(String(64))
    actor: Mapped[str | None] = mapped_column(String(120))
    html_url: Mapped[str | None] = mapped_column(String(500))
    occurred_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)

    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSONType, default=list)
    details: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    project: Mapped[Project] = relationship(back_populates="ci_events")
