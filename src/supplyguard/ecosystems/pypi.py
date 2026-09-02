"""PyPI / Python ecosystem adapter."""

from __future__ import annotations

import json
import re
import tomllib
from collections import deque
from typing import Any, ClassVar

from supplyguard.clients.http import HttpClient
from supplyguard.core.types import DependencyGraph, PackageMetadata, ResolvedPackage
from supplyguard.ecosystems.base import EcosystemAdapter, ManifestParseError, register
from supplyguard.ecosystems.versions import parse_pep440
from supplyguard.utils.dates import parse_iso

PYPI_JSON = "https://pypi.org/pypi"
PYPISTATS = "https://pypistats.org/api/packages"

_REQUIREMENT = re.compile(
    r"""^\s*
    (?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)      # distribution name
    (?:\[(?P<extras>[^\]]*)\])?               # optional extras
    \s*(?P<op>==|===)\s*                      # only pinned requirements resolve
    (?P<version>[^\s;#\\]+)
    """,
    re.VERBOSE,
)
_UNPINNED = re.compile(r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(?P<rest>.*)$")


@register
class PyPIAdapter(EcosystemAdapter):
    name: ClassVar[str] = "pypi"
    display_name: ClassVar[str] = "PyPI (Python)"
    osv_ecosystem: ClassVar[str] = "PyPI"
    ghsa_ecosystem: ClassVar[str] = "PIP"
    manifest_patterns: ClassVar[tuple[str, ...]] = (
        "requirements*.txt",
        "poetry.lock",
        "Pipfile.lock",
        "pyproject.toml",
        "uv.lock",
    )
    lockfile_patterns: ClassVar[tuple[str, ...]] = ("poetry.lock", "Pipfile.lock", "uv.lock")
    registry_config_patterns: ClassVar[tuple[str, ...]] = ("pip.conf", "pip.ini", ".pypirc")

    # -- naming -------------------------------------------------------------
    def normalize_name(self, name: str) -> str:
        """PEP 503 normalisation: the registry treats these names as identical."""
        return re.sub(r"[-_.]+", "-", name.strip()).lower()

    def registry_package_url(self, name: str) -> str:
        return f"https://pypi.org/project/{name}/"

    def parse_version(self, version: str) -> tuple:
        return parse_pep440(version)

    def looks_private(self, name: str) -> bool:
        # PyPI has no namespaces, so internal packages announce themselves only
        # through naming convention (`acme-internal-client`, `corp_shared_lib`).
        return bool(re.match(r"^(internal|private|corp|acme|company)[-_]", name.lower()))

    # -- manifest parsing ---------------------------------------------------
    def parse_manifest(self, content: str, filename: str) -> DependencyGraph:
        base = filename.rsplit("/", 1)[-1]
        if base == "poetry.lock":
            return self._parse_poetry_lock(content, base)
        if base == "uv.lock":
            return self._parse_uv_lock(content, base)
        if base == "Pipfile.lock":
            return self._parse_pipfile_lock(content, base)
        if base == "pyproject.toml":
            return self._parse_pyproject(content, base)
        return self._parse_requirements(content, base)

    # ---- requirements.txt --------------------------------------------------
    def _parse_requirements(self, content: str, filename: str) -> DependencyGraph:
        graph = DependencyGraph(ecosystem=self.name, manifest_filename=filename)
        unpinned: list[str] = []

        for raw_line in _join_continuations(content):
            line = raw_line.split(" #", 1)[0].strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("-"):
                if line.startswith(("-r", "--requirement", "-c", "--constraint")):
                    graph.warnings.append(
                        f"Skipped include `{line}`: referenced file was not uploaded."
                    )
                continue
            # Strip environment markers and inline hashes before matching.
            requirement = line.split(";", 1)[0].split("--hash", 1)[0].strip()
            match = _REQUIREMENT.match(requirement)
            if match:
                graph.direct_names.add(match.group("name"))
                graph.add(
                    ResolvedPackage(
                        ecosystem=self.name,
                        name=match.group("name"),
                        version=match.group("version").strip(),
                        depth=0,
                        is_direct=True,
                        raw={"extras": match.group("extras"), "line": line},
                    )
                )
            elif (loose := _UNPINNED.match(requirement)) and loose.group("rest").strip():
                unpinned.append(requirement)

        if unpinned:
            graph.warnings.append(
                f"{len(unpinned)} requirement(s) are not pinned with `==` and were "
                f"skipped (e.g. {unpinned[0]!r}). Upload a lockfile for full coverage."
            )
        graph.warnings.append(
            "requirements.txt is flat: transitive relationships are unknown, so "
            "every package is reported as direct."
        )
        return graph

    # ---- poetry.lock -------------------------------------------------------
    def _parse_poetry_lock(self, content: str, filename: str) -> DependencyGraph:
        data = _load_toml(content, filename)
        graph = DependencyGraph(ecosystem=self.name, manifest_filename=filename)

        entries: dict[str, dict] = {}
        edges: dict[str, list[str]] = {}
        for entry in data.get("package") or []:
            pkg_name = entry.get("name")
            version = entry.get("version")
            if not pkg_name or not version:
                continue
            key = self.normalize_name(pkg_name)
            entries[key] = entry
            deps = entry.get("dependencies") or {}
            edges[key] = [self.normalize_name(d) for d in deps]

        self._build_from_edges(graph, entries, edges)
        return graph

    # ---- uv.lock -----------------------------------------------------------
    def _parse_uv_lock(self, content: str, filename: str) -> DependencyGraph:
        data = _load_toml(content, filename)
        graph = DependencyGraph(ecosystem=self.name, manifest_filename=filename)

        entries: dict[str, dict] = {}
        edges: dict[str, list[str]] = {}
        for entry in data.get("package") or []:
            pkg_name, version = entry.get("name"), entry.get("version")
            if not pkg_name or not version:
                continue
            key = self.normalize_name(pkg_name)
            entries[key] = entry
            deps = entry.get("dependencies") or []
            edges[key] = [
                self.normalize_name(d["name"]) for d in deps if isinstance(d, dict) and d.get("name")
            ]
        self._build_from_edges(graph, entries, edges)
        return graph

    def _build_from_edges(
        self, graph: DependencyGraph, entries: dict[str, dict], edges: dict[str, list[str]]
    ) -> None:
        """Derive depth from the lockfile's own dependency edges.

        A lockfile does not say which packages the project asked for directly,
        so roots are inferred: anything nothing else depends on is a root. This
        matches the true direct set for almost every real project.
        """
        depended_on = {child for children in edges.values() for child in children}
        roots = [k for k in entries if k not in depended_on] or list(entries)

        depth: dict[str, int] = dict.fromkeys(roots, 0)
        queue: deque[str] = deque(roots)
        while queue:
            key = queue.popleft()
            for child in edges.get(key, []):
                if child in entries and depth.get(child, 10**6) > depth[key] + 1:
                    depth[child] = depth[key] + 1
                    queue.append(child)

        for key, entry in entries.items():
            node_depth = depth.get(key, 1)
            pkg = ResolvedPackage(
                ecosystem=self.name,
                name=entry["name"],
                version=str(entry["version"]),
                depth=node_depth,
                is_direct=node_depth == 0,
                is_dev=_is_dev_group(entry),
                raw={"source": (entry.get("source") or {}).get("type")},
            )
            graph.add(pkg)
            if node_depth == 0:
                graph.direct_names.add(entry["name"])

        version_of = {k: str(e["version"]) for k, e in entries.items()}
        for key, children in edges.items():
            if key not in entries:
                continue
            parent_key = f"{entries[key]['name']}@{version_of[key]}"
            for child in children:
                if child in entries:
                    graph.link(parent_key, f"{entries[child]['name']}@{version_of[child]}")

    # ---- Pipfile.lock ------------------------------------------------------
    def _parse_pipfile_lock(self, content: str, filename: str) -> DependencyGraph:
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ManifestParseError(f"{filename} is not valid JSON: {exc}") from exc
        graph = DependencyGraph(ecosystem=self.name, manifest_filename=filename)
        for section, is_dev in (("default", False), ("develop", True)):
            for pkg_name, entry in (data.get(section) or {}).items():
                version = str(entry.get("version") or "").lstrip("=")
                if not version:
                    continue
                graph.direct_names.add(pkg_name)
                graph.add(
                    ResolvedPackage(
                        ecosystem=self.name,
                        name=pkg_name,
                        version=version,
                        depth=0,
                        is_direct=True,
                        is_dev=is_dev,
                        integrity=(entry.get("hashes") or [None])[0],
                    )
                )
        graph.warnings.append(
            "Pipfile.lock records no dependency edges; depth is reported as direct."
        )
        return graph

    # ---- pyproject.toml ----------------------------------------------------
    def _parse_pyproject(self, content: str, filename: str) -> DependencyGraph:
        data = _load_toml(content, filename)
        graph = DependencyGraph(ecosystem=self.name, manifest_filename=filename)
        graph.warnings.append(
            "pyproject.toml declares version ranges, not resolved versions. "
            "Upload poetry.lock or uv.lock for transitive coverage."
        )

        def add(pkg_name: str, spec: Any, is_dev: bool) -> None:
            if pkg_name.lower() == "python":
                return
            text = spec if isinstance(spec, str) else (spec or {}).get("version", "*")
            graph.direct_names.add(pkg_name)
            graph.add(
                ResolvedPackage(
                    ecosystem=self.name,
                    name=pkg_name,
                    version=_strip_specifier(str(text)),
                    depth=0,
                    is_direct=True,
                    is_dev=is_dev,
                    raw={"declared_range": text, "unresolved": True},
                )
            )

        for requirement in (data.get("project") or {}).get("dependencies") or []:
            parsed = _UNPINNED.match(str(requirement))
            if parsed:
                add(parsed.group("name"), parsed.group("rest"), False)
        for group, requirements in (
            (data.get("project") or {}).get("optional-dependencies") or {}
        ).items():
            for requirement in requirements:
                parsed = _UNPINNED.match(str(requirement))
                if parsed:
                    add(parsed.group("name"), parsed.group("rest"), group in ("dev", "test"))

        poetry = ((data.get("tool") or {}).get("poetry")) or {}
        for pkg_name, spec in (poetry.get("dependencies") or {}).items():
            add(pkg_name, spec, False)
        for group_name, group in (poetry.get("group") or {}).items():
            for pkg_name, spec in (group.get("dependencies") or {}).items():
                add(pkg_name, spec, group_name in ("dev", "test"))
        return graph

    # -- registry -----------------------------------------------------------
    async def fetch_metadata(self, name: str, http: HttpClient) -> PackageMetadata:
        data = await http.get_json(f"{PYPI_JSON}/{name}/json", ttl=86_400)
        if data is None:
            return PackageMetadata(ecosystem=self.name, name=name, exists=False)

        info = data.get("info") or {}
        releases: dict[str, list[dict]] = data.get("releases") or {}

        published: dict[str, Any] = {}
        for version, files in releases.items():
            stamps = [
                parse_iso(f.get("upload_time_iso_8601") or f.get("upload_time"))
                for f in files or []
            ]
            stamps = [s for s in stamps if s]
            if stamps:
                published[version] = min(stamps)

        latest = info.get("version")
        repository = _pypi_repo_url(info)
        readme = info.get("description") or ""

        # PyPI cannot show us file contents, but the *shape* of the release is
        # itself a signal: with no wheel, pip builds from the sdist and executes
        # setup.py on the installing machine.
        latest_files = releases.get(latest) or []
        has_wheel = any(f.get("packagetype") == "bdist_wheel" for f in latest_files)
        has_sdist = any(f.get("packagetype") == "sdist" for f in latest_files)
        install_scripts: dict[str, str] = {}
        if has_sdist and not has_wheel:
            install_scripts["setup.py"] = (
                "Release ships an sdist with no wheel, so pip builds from source "
                "and executes setup.py/build hooks at install time."
            )

        return PackageMetadata(
            ecosystem=self.name,
            name=info.get("name", name),
            exists=True,
            latest_version=latest,
            description=info.get("summary"),
            repository_url=repository,
            homepage=info.get("home_page") or (info.get("project_urls") or {}).get("Homepage"),
            license=info.get("license") or _license_from_classifiers(info),
            first_published=min(published.values()) if published else None,
            last_published=max(published.values()) if published else None,
            version_published=published,
            maintainers=[
                v for v in (info.get("author"), info.get("maintainer")) if v
            ],
            has_readme=len(readme.strip()) > 0,
            readme_length=len(readme),
            install_scripts=install_scripts,
            yanked=bool(info.get("yanked")),
            raw={
                "versions": sorted(releases),
                "has_wheel": has_wheel,
                "has_sdist": has_sdist,
                "requires_dist": info.get("requires_dist") or [],
                "classifiers": info.get("classifiers") or [],
            },
        )

    async def fetch_download_count(self, name: str, http: HttpClient) -> int | None:
        # PyPI's own JSON API stopped reporting download counts; pypistats is
        # the conventional stand-in. Treat failure as "unknown", never as zero.
        try:
            data = await http.get_json(f"{PYPISTATS}/{self.normalize_name(name)}/recent", ttl=86_400)
        except Exception:
            return None
        if not data:
            return None
        return (data.get("data") or {}).get("last_month")


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _load_toml(content: str, filename: str) -> dict:
    try:
        return tomllib.loads(content)
    except tomllib.TOMLDecodeError as exc:
        raise ManifestParseError(f"{filename} is not valid TOML: {exc}") from exc


def _join_continuations(content: str) -> list[str]:
    """Join backslash-continued requirement lines (common with --hash pins)."""
    lines: list[str] = []
    buffer = ""
    for line in content.splitlines():
        if line.rstrip().endswith("\\"):
            buffer += line.rstrip()[:-1] + " "
        else:
            lines.append(buffer + line)
            buffer = ""
    if buffer:
        lines.append(buffer)
    return lines


def _is_dev_group(entry: dict) -> bool:
    if entry.get("category") == "dev":  # poetry lock < 2.0
        return True
    groups = entry.get("groups") or []
    return bool(groups) and all(g in ("dev", "test") for g in groups)


def _strip_specifier(spec: str) -> str:
    match = re.search(r"\d+(?:\.\d+)*(?:[a-z0-9.\-]*)", spec)
    return match.group(0) if match else spec.strip() or "*"


def _pypi_repo_url(info: dict) -> str | None:
    urls = info.get("project_urls") or {}
    for key in ("Source", "Source Code", "Repository", "Code", "GitHub", "Homepage"):
        value = urls.get(key)
        if value and re.search(r"github\.com|gitlab\.com|bitbucket\.org|codeberg\.org", value):
            return value
    for value in urls.values():
        if value and re.search(r"github\.com|gitlab\.com|bitbucket\.org", str(value)):
            return str(value)
    home = info.get("home_page")
    if home and re.search(r"github\.com|gitlab\.com|bitbucket\.org", home):
        return home
    return None


def _license_from_classifiers(info: dict) -> str | None:
    for classifier in info.get("classifiers") or []:
        if classifier.startswith("License :: "):
            return classifier.rsplit(" :: ", 1)[-1]
    return None
