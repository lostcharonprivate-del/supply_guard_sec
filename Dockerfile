# syntax=docker/dockerfile:1

# --- stage 1: build the dashboard ------------------------------------------
FROM node:22-alpine AS frontend
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
# `npm ci` installs exactly the committed lockfile and fails if the two have
# drifted. A tool that reports unpinned dependencies should not have any.
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# --- stage 2: runtime -------------------------------------------------------
FROM python:3.12-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install dependencies before the source so that editing code does not
# invalidate the dependency layer on every rebuild.
COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN pip install --no-cache-dir -e .

COPY data/ ./data/
COPY alembic.ini ./
COPY migrations/ ./migrations/
COPY --from=frontend /build/dist ./frontend/dist

# Run as an unprivileged user: this service fetches and parses untrusted
# manifests from the internet, so it should not be root if that parsing is ever
# made to misbehave.
RUN useradd --create-home --uid 10001 supplyguard && chown -R supplyguard:supplyguard /app
USER supplyguard

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4).status == 200 else 1)"

CMD ["uvicorn", "supplyguard.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
