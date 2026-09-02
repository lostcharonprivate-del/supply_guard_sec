"""FastAPI application."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

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

    _mount_dashboard(app, settings.api_prefix)

    @app.exception_handler(ValueError)
    async def value_error_handler(request: Request, exc: ValueError) -> JSONResponse:
        # Parser and validation failures are the caller's problem, not a 500.
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content={"detail": str(exc)}
        )

    return app


def _mount_dashboard(app: FastAPI, api_prefix: str) -> None:
    """Serve the built dashboard from the API, when it has been built.

    Keeps the deployed stack to a single origin, which removes CORS from the
    picture entirely. In development the Vite dev server proxies to this API
    instead, so nothing is mounted and the API runs alone.
    """
    dist = Path(__file__).resolve().parents[3] / "frontend" / "dist"
    if not (dist / "index.html").exists():
        logger.info("No built dashboard at %s; serving the API only.", dist)
        return

    assets = dist / "assets"
    if assets.is_dir():
        app.mount("/assets", StaticFiles(directory=assets), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    async def serve_dashboard(path: str) -> FileResponse:
        """Return index.html for any unmatched path.

        The dashboard is a single-page app with client-side routing, so a deep
        link such as /scans/<id> must still be served the app shell. API and
        docs routes are matched before this handler, but an unknown path under
        the API prefix should 404 as JSON rather than silently return HTML.
        """
        if path.startswith(api_prefix.lstrip("/")) or path in ("health", "openapi.json"):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found.")
        candidate = (dist / path).resolve()
        # Only serve files that really sit inside dist: `path` is caller-controlled.
        if path and candidate.is_file() and candidate.is_relative_to(dist.resolve()):
            return FileResponse(candidate)
        return FileResponse(dist / "index.html")

    logger.info("Serving the dashboard from %s", dist)


app = create_app()
