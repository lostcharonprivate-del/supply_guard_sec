"""FastAPI application."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from supplyguard import __version__
from supplyguard.api.routes import auth, ci, meta, projects, scans
from supplyguard.config import get_settings
from supplyguard.db.session import create_all, dispose_engine
from supplyguard.ecosystems import ecosystem_names

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    for problem in settings.validate_for_production():
        # Loud, but not fatal: refusing to boot would be worse than running
        # with a warning in a demo environment.
        logger.warning("INSECURE CONFIGURATION: %s", problem)
    try:
        await create_all()
    except Exception as exc:
        logger.error(
            "Could not reach the database at startup (%s). The API will start, "
            "but every persistent endpoint will fail until it is available.", exc
        )
    yield
    await dispose_engine()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="SupplyGuard API",
        version=__version__,
        summary="Supply chain security analysis for npm, PyPI, RubyGems and Maven.",
        description=(
            "Scans dependency manifests for known vulnerabilities, malicious "
            "packages, typosquats and dependency-confusion exposure, and monitors "
            "GitHub Actions workflows for build-integrity problems.\n\n"
            "Every detector documents its own false-positive and false-negative "
            "limitations at `/api/v1/detectors`."
        ),
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    prefix = settings.api_prefix
    app.include_router(auth.router, prefix=prefix)
    app.include_router(projects.router, prefix=prefix)
    app.include_router(scans.router, prefix=prefix)
    app.include_router(ci.router, prefix=prefix)
    app.include_router(meta.router, prefix=prefix)

    @app.get("/health", tags=["meta"])
    async def health() -> dict:
        return {
            "status": "ok",
            "version": __version__,
            "ecosystems": ecosystem_names(),
        }

    @app.exception_handler(ValueError)
    async def value_error_handler(request: Request, exc: ValueError) -> JSONResponse:
        # Parser and validation failures are the caller's problem, not a 500.
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content={"detail": str(exc)}
        )

    return app


app = create_app()
