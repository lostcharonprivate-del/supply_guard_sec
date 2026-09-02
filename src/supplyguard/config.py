"""Application settings, loaded from the environment."""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore", env_prefix=""
    )

    # -- app ----------------------------------------------------------------
    app_name: str = "SupplyGuard"
    environment: str = Field(default="development")
    debug: bool = False
    api_prefix: str = "/api/v1"
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173"])

    # -- storage ------------------------------------------------------------
    database_url: str = Field(
        default="postgresql+asyncpg://supplyguard:supplyguard@localhost:5432/supplyguard"
    )
    redis_url: str = Field(default="redis://localhost:6379/0")

    # -- auth ---------------------------------------------------------------
    #: Must be overridden in any deployment; startup refuses the default when
    #: environment is not "development".
    jwt_secret: str = Field(default="change-me-in-production")
    jwt_algorithm: str = "HS256"
    jwt_expiry_minutes: int = 60 * 12
    github_client_id: str | None = None
    github_client_secret: str | None = None

    # -- external APIs ------------------------------------------------------
    github_token: str | None = None
    #: TTLs in seconds. Package metadata changes slowly; advisories should not
    #: be stale for more than a few hours.
    cache_ttl_package_metadata: int = 86_400
    cache_ttl_vulnerabilities: int = 21_600
    http_timeout_seconds: float = 15.0
    http_max_concurrency: int = 16

    # -- scanning -----------------------------------------------------------
    max_upload_bytes: int = 10 * 1024 * 1024
    max_files_per_scan: int = 25
    scan_timeout_seconds: int = 900

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in ("production", "prod")

    def validate_for_production(self) -> list[str]:
        """Configuration that is acceptable locally but not in production."""
        problems: list[str] = []
        if self.is_production:
            if self.jwt_secret == "change-me-in-production":
                problems.append("JWT_SECRET is still the default value.")
            if self.debug:
                problems.append("DEBUG is enabled.")
            if "*" in self.cors_origins:
                problems.append("CORS_ORIGINS allows any origin.")
        return problems


@lru_cache
def get_settings() -> Settings:
    return Settings()
