"""Request and response models for the HTTP API."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from supplyguard.config import get_settings


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# -- auth -------------------------------------------------------------------

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=10, max_length=72)
    display_name: str | None = Field(default=None, max_length=120)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in_minutes: int


class UserResponse(ORMModel):
    id: str
    email: str
    display_name: str | None
    github_login: str | None
    created_at: datetime


# -- projects ---------------------------------------------------------------

class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = None
    repository_url: str | None = Field(default=None, max_length=500)
    #: Detector overrides, e.g. {"organization_scopes": ["@acme"]}.
    settings: dict[str, Any] = Field(default_factory=dict)


class ProjectUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = None
    repository_url: str | None = None
    settings: dict[str, Any] | None = None


class ProjectResponse(ORMModel):
    id: str
    name: str
    description: str | None
    repository_url: str | None
    settings: dict[str, Any]
    created_at: datetime
    updated_at: datetime
    latest_risk_score: float | None = None
    latest_risk_grade: str | None = None
    scan_count: int = 0


# -- scans ------------------------------------------------------------------

class ScanCreate(BaseModel):
    """Submit a scan.

    Supply `files` (filename -> content) or `repository_url`, or both.
    """

    files: dict[str, str] = Field(default_factory=dict)
    repository_url: str | None = None
    ecosystems: list[str] | None = None
    detectors: list[str] | None = None
    project_id: str | None = None
    project_name: str | None = None

    @field_validator("files")
    @classmethod
    def _check_size(cls, value: dict[str, str]) -> dict[str, str]:
        settings = get_settings()
        if len(value) > settings.max_files_per_scan:
            raise ValueError(
                f"At most {settings.max_files_per_scan} files may be submitted in one scan."
            )
        total = sum(len(content.encode("utf-8")) for content in value.values())
        if total > settings.max_upload_bytes:
            raise ValueError(
                f"Uploaded content exceeds {settings.max_upload_bytes // (1024 * 1024)}MB."
            )
        return value


class ScanAccepted(BaseModel):
    scan_id: str
    project_id: str
    status: str
    poll_url: str


class EvidenceResponse(BaseModel):
    label: str
    detail: str
    weight: float = 0.0


class FindingResponse(ORMModel):
    id: int
    category: str
    severity: str
    title: str
    description: str
    detector: str
    ecosystem: str | None
    package_name: str | None
    package_version: str | None
    identifier: str | None
    cvss_score: float | None
    affected_range: str | None
    fixed_version: str | None
    remediation: str | None
    confidence: float
    depth: int
    is_direct: bool
    risk_contribution: float
    references: list[str]
    evidence: list[dict[str, Any]]
    details: dict[str, Any]


class DependencyResponse(ORMModel):
    ecosystem: str
    name: str
    version: str
    depth: int
    is_direct: bool
    is_dev: bool
    manifest_filename: str | None
    parents: list[str]


class ScanResponse(ORMModel):
    id: str
    project_id: str
    status: str
    risk_score: float | None
    risk_grade: str | None
    package_count: int
    finding_count: int
    duration_seconds: float | None
    started_at: datetime | None
    finished_at: datetime | None
    error: str | None
    summary: dict[str, Any]
    created_at: datetime


class ScanDetailResponse(ScanResponse):
    findings: list[FindingResponse] = Field(default_factory=list)


class DependencyTreeNode(BaseModel):
    key: str
    name: str
    version: str
    ecosystem: str
    depth: int
    is_direct: bool
    is_dev: bool
    #: Worst severity among this node's findings, or None.
    severity: str | None = None
    finding_count: int = 0
    children: list[DependencyTreeNode] = Field(default_factory=list)


class RiskTrendPoint(BaseModel):
    scan_id: str
    created_at: datetime
    risk_score: float | None
    risk_grade: str | None
    finding_count: int


# -- CI ---------------------------------------------------------------------

class CiEventResponse(ORMModel):
    id: int
    external_id: str
    provider: str
    event_type: str
    severity: str
    title: str
    description: str
    remediation: str | None
    repository: str | None
    workflow_name: str | None
    workflow_path: str | None
    commit_sha: str | None
    actor: str | None
    html_url: str | None
    occurred_at: datetime | None
    evidence: list[dict[str, Any]]
    details: dict[str, Any]
    created_at: datetime


class CiScanRequest(BaseModel):
    repository_url: str | None = None
    #: How many recent workflow runs to inspect.
    run_limit: int = Field(default=30, ge=1, le=100)


# -- meta -------------------------------------------------------------------

class DetectorInfo(BaseModel):
    name: str
    category: str
    description: str
    requires_network: bool
    known_false_positives: list[str]
    known_false_negatives: list[str]


class EcosystemInfo(BaseModel):
    name: str
    display_name: str
    manifest_patterns: list[str]
    lockfile_patterns: list[str]
    supports_scopes: bool
    download_metric: str
    reference_set_size: int


DependencyTreeNode.model_rebuild()
