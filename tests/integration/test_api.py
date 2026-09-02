"""API integration tests against a live app and a real (SQLite) database."""

from __future__ import annotations

import asyncio

import pytest
from httpx import ASGITransport, AsyncClient

from supplyguard.db.session import create_all, dispose_engine, reset_engine_for_testing
from tests.conftest import load_fixture


@pytest.fixture
async def client(tmp_path, monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "test-secret-not-a-real-one")
    # No Redis in the test environment: scans fall back to in-process execution,
    # which is exactly the path a reviewer running `supplyguard serve` takes.
    monkeypatch.setenv("REDIS_URL", "")
    from supplyguard.config import get_settings

    get_settings.cache_clear()
    reset_engine_for_testing(f"sqlite+aiosqlite:///{tmp_path/'test.db'}")
    await create_all()

    from supplyguard.api.app import create_app

    app = create_app()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as instance:
        yield instance
    await dispose_engine()
    get_settings.cache_clear()


async def register(client: AsyncClient, email: str = "dev@example.com") -> dict:
    response = await client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "a-sufficiently-long-password"},
    )
    assert response.status_code == 201, response.text
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


class TestMeta:
    async def test_health(self, client: AsyncClient) -> None:
        response = await client.get("/health")
        assert response.status_code == 200
        assert set(response.json()["ecosystems"]) == {"npm", "pypi", "rubygems", "maven"}

    async def test_detectors_expose_their_own_limitations(self, client: AsyncClient) -> None:
        response = await client.get("/api/v1/detectors")
        assert response.status_code == 200
        detectors = response.json()
        assert {d["name"] for d in detectors} >= {
            "vulnerability", "typosquat", "malicious", "dependency_confusion", "staleness"
        }
        # Every detector must state what it gets wrong.
        for detector in detectors:
            assert detector["known_false_positives"], detector["name"]
            assert detector["known_false_negatives"], detector["name"]

    async def test_ecosystems_report_reference_set_sizes(self, client: AsyncClient) -> None:
        response = await client.get("/api/v1/ecosystems")
        by_name = {e["name"]: e for e in response.json()}
        assert by_name["npm"]["reference_set_size"] > 1000
        assert by_name["maven"]["supports_scopes"] is True


class TestAuth:
    async def test_register_then_use_the_token(self, client: AsyncClient) -> None:
        headers = await register(client)
        response = await client.get("/api/v1/auth/me", headers=headers)
        assert response.status_code == 200
        assert response.json()["email"] == "dev@example.com"

    async def test_duplicate_registration_is_rejected(self, client: AsyncClient) -> None:
        await register(client)
        response = await client.post(
            "/api/v1/auth/register",
            json={"email": "dev@example.com", "password": "another-long-password"},
        )
        assert response.status_code == 409

    async def test_short_passwords_are_rejected(self, client: AsyncClient) -> None:
        response = await client.post(
            "/api/v1/auth/register", json={"email": "a@b.co", "password": "short"}
        )
        assert response.status_code == 422

    async def test_login_with_wrong_password_fails(self, client: AsyncClient) -> None:
        await register(client)
        response = await client.post(
            "/api/v1/auth/login", json={"email": "dev@example.com", "password": "wrong-password"}
        )
        assert response.status_code == 401

    async def test_protected_routes_require_a_token(self, client: AsyncClient) -> None:
        assert (await client.get("/api/v1/projects")).status_code == 401

    async def test_a_tampered_token_is_rejected(self, client: AsyncClient) -> None:
        headers = await register(client)
        headers["Authorization"] += "tampered"
        assert (await client.get("/api/v1/auth/me", headers=headers)).status_code == 401


class TestProjectIsolation:
    async def test_one_user_cannot_see_anothers_project(self, client: AsyncClient) -> None:
        alice = await register(client, "alice@example.com")
        bob = await register(client, "bob@example.com")

        created = await client.post(
            "/api/v1/projects", json={"name": "alice-project"}, headers=alice
        )
        project_id = created.json()["id"]

        assert (await client.get("/api/v1/projects", headers=bob)).json() == []
        # 404 rather than 403: confirming the id exists would leak its existence.
        response = await client.get(f"/api/v1/projects/{project_id}", headers=bob)
        assert response.status_code == 404

    async def test_duplicate_project_names_per_user_are_rejected(
        self, client: AsyncClient
    ) -> None:
        headers = await register(client)
        await client.post("/api/v1/projects", json={"name": "dup"}, headers=headers)
        second = await client.post("/api/v1/projects", json={"name": "dup"}, headers=headers)
        assert second.status_code == 409


class TestScanFlow:
    async def test_scan_submits_runs_and_reports(self, client: AsyncClient) -> None:
        headers = await register(client)
        submitted = await client.post(
            "/api/v1/scans",
            json={
                "files": {"pom.xml": load_fixture("maven", "pom.xml")},
                "project_name": "demo",
                "detectors": ["typosquat"],  # offline-capable, so this is fast
            },
            headers=headers,
        )
        assert submitted.status_code == 202, submitted.text
        scan_id = submitted.json()["scan_id"]

        for _ in range(60):
            await asyncio.sleep(0.25)
            polled = await client.get(f"/api/v1/scans/{scan_id}", headers=headers)
            assert polled.status_code == 200
            if polled.json()["status"] in ("completed", "failed"):
                break
        payload = polled.json()
        assert payload["status"] == "completed", payload.get("error")
        assert payload["package_count"] == 4
        assert payload["risk_grade"] in {"A", "B", "C", "D", "F"}

        dependencies = await client.get(
            f"/api/v1/scans/{scan_id}/dependencies", headers=headers
        )
        names = {d["name"] for d in dependencies.json()}
        assert "org.apache.logging.log4j:log4j-core" in names

        tree = await client.get(f"/api/v1/scans/{scan_id}/tree", headers=headers)
        assert tree.status_code == 200
        assert len(tree.json()) == 4

    async def test_scan_without_files_or_repository_is_rejected(
        self, client: AsyncClient
    ) -> None:
        headers = await register(client)
        response = await client.post("/api/v1/scans", json={}, headers=headers)
        assert response.status_code == 422

    async def test_another_user_cannot_read_a_scan(self, client: AsyncClient) -> None:
        alice = await register(client, "alice@example.com")
        bob = await register(client, "bob@example.com")
        submitted = await client.post(
            "/api/v1/scans",
            json={
                "files": {"pom.xml": load_fixture("maven", "pom.xml")},
                "detectors": ["typosquat"],
            },
            headers=alice,
        )
        scan_id = submitted.json()["scan_id"]
        assert (await client.get(f"/api/v1/scans/{scan_id}", headers=bob)).status_code == 404

    async def test_too_many_files_is_rejected(self, client: AsyncClient) -> None:
        headers = await register(client)
        response = await client.post(
            "/api/v1/scans",
            json={"files": {f"requirements-{i}.txt": "x==1.0" for i in range(200)}},
            headers=headers,
        )
        assert response.status_code == 422
