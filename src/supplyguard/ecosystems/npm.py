"""npm / Node.js ecosystem adapter."""

from __future__ import annotations

import json
import re
from collections import deque
from datetime import datetime
from typing import Any, ClassVar

from supplyguard.clients.http import HttpClient
from supplyguard.core.types import DependencyGraph, PackageMetadata, ResolvedPackage
from supplyguard.ecosystems.base import EcosystemAdapter, ManifestParseError, register
from supplyguard.ecosystems.versions import parse_semver
from supplyguard.utils.dates import parse_iso

REGISTRY = "https://registry.npmjs.org"
DOWNLOADS_API = "https://api.npmjs.org/downloads/point/last-month"
SEARCH_API = "https://registry.npmjs.org/-/v1/search"

#: npm lifecycle hooks that execute automatically on `npm install`.
INSTALL_HOOKS = ("preinstall", "install", "postinstall", "prepare", "prepublish")


@register
class NpmAdapter(EcosystemAdapter):
    name: ClassVar[str] = "npm"
    display_name: ClassVar[str] = "npm (JavaScript/Node)"
    osv_ecosystem: ClassVar[str] = "npm"
    ghsa_ecosystem: ClassVar[str] = "NPM"
    manifest_patterns: ClassVar[tuple[str, ...]] = (
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "package.json",
    )
    lockfile_patterns: ClassVar[tuple[str, ...]] = (
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
    )
    registry_config_patterns: ClassVar[tuple[str, ...]] = (".npmrc", ".yarnrc", ".yarnrc.yml")
    supports_scopes: ClassVar[bool] = True

    # -- naming -------------------------------------------------------------
    def normalize_name(self, name: str) -> str:
        # npm names are case-sensitive in theory but the registry lowercases
        # new publishes; lowercasing is the right comparison key.
        return name.strip().lower()

    def scope_of(self, name: str) -> str | None:
        if name.startswith("@") and "/" in name:
            return name.split("/", 1)[0]
        return None

    def registry_package_url(self, name: str) -> str:
        return f"https://www.npmjs.com/package/{name}"

    def parse_version(self, version: str) -> tuple:
        return parse_semver(version)

    def looks_private(self, name: str) -> bool:
        """Heuristic: a scoped package under an org-looking scope."""
        return self.scope_of(name) is not None

    # -- manifest parsing ---------------------------------------------------
    def parse_manifest(self, content: str, filename: str) -> DependencyGraph:
        base = filename.rsplit("/", 1)[-1]
        if base == "yarn.lock":
            return self._parse_yarn_lock(content, base)
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ManifestParseError(f"{base} is not valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ManifestParseError(f"{base} must contain a JSON object")

        if base == "package.json":
            return self._parse_package_json(data, base)
        if "packages" in data:  # lockfileVersion 2 or 3
            return self._parse_lock_v2(data, base)
        if "dependencies" in data or "lockfileVersion" in data:  # v1
            return self._parse_lock_v1(data, base)
        raise ManifestParseError(f"{base} does not look like an npm lockfile")

    # ---- package.json (declaration only, versions are ranges) -------------
    def _parse_package_json(self, data: dict, filename: str) -> DependencyGraph:
        graph = DependencyGraph(ecosystem=self.name, manifest_filename=filename)
        graph.warnings.append(
            "package.json declares version ranges, not resolved versions. "
            "Upload package-lock.json for transitive coverage and exact matching."
        )
        for field_name, is_dev in (
            ("dependencies", False),
            ("devDependencies", True),
            ("optionalDependencies", False),
        ):
            for pkg_name, spec in (data.get(field_name) or {}).items():
                graph.direct_names.add(pkg_name)
                graph.add(
                    ResolvedPackage(
                        ecosystem=self.name,
                        name=pkg_name,
                        version=_strip_range(str(spec)),
                        depth=0,
                        is_direct=True,
                        is_dev=is_dev,
                        raw={"declared_range": spec, "unresolved": True},
                    )
                )
        return graph

    # ---- lockfileVersion 2/3 ----------------------------------------------
    def _parse_lock_v2(self, data: dict, filename: str) -> DependencyGraph:
        graph = DependencyGraph(ecosystem=self.name, manifest_filename=filename)
        packages: dict[str, dict] = data.get("packages") or {}
        root = packages.get("", {})

        direct: dict[str, bool] = {}  # name -> is_dev
        for field_name, is_dev in (
            ("dependencies", False),
            ("devDependencies", True),
            ("optionalDependencies", False),
        ):
            for pkg_name in (root.get(field_name) or {}):
                direct[pkg_name] = direct.get(pkg_name, True) and is_dev
        graph.direct_names.update(direct)

        # Map install path -> package name for npm's resolution walk-up.
        by_path: dict[str, tuple[str, dict]] = {}
        for path, entry in packages.items():
            if not path or not isinstance(entry, dict):
                continue
            if entry.get("link"):  # workspace symlink; the target is listed too
                continue
            pkg_name = entry.get("name") or _name_from_path(path)
            if pkg_name and entry.get("version"):
                by_path[path] = (pkg_name, entry)

        def resolve(from_path: str, dep_name: str) -> str | None:
            """npm resolution: walk up the node_modules chain from `from_path`."""
            prefix = from_path
            while True:
                candidate = f"{prefix}/node_modules/{dep_name}" if prefix else f"node_modules/{dep_name}"
                if candidate in by_path:
                    return candidate
                if not prefix:
                    return None
                idx = prefix.rfind("/node_modules/")
                prefix = prefix[:idx] if idx != -1 else ""

        # BFS from the root so `depth` reflects real dependency distance rather
        # than how npm happened to hoist the package on disk.
        queue: deque[tuple[str, int, bool, str | None]] = deque()
        for dep_name, is_dev in direct.items():
            root_path = resolve("", dep_name)
            if root_path:
                queue.append((root_path, 0, is_dev, None))

        seen: dict[str, int] = {}
        while queue:
            path, depth, is_dev, parent_key = queue.popleft()
            pkg_name, entry = by_path[path]
            node = graph.add(
                ResolvedPackage(
                    ecosystem=self.name,
                    name=pkg_name,
                    version=str(entry["version"]),
                    depth=depth,
                    is_direct=depth == 0,
                    is_dev=is_dev or bool(entry.get("dev")),
                    parents=(parent_key,) if parent_key else (),
                    integrity=entry.get("integrity"),
                    resolved_url=entry.get("resolved"),
                    raw=_npm_extras(entry),
                )
            )
            if parent_key:
                graph.link(parent_key, node.key)
            if path in seen and seen[path] <= depth:
                continue
            seen[path] = depth
            for child_name in (entry.get("dependencies") or {}):
                child_path = resolve(path, child_name)
                if child_path:
                    queue.append((child_path, depth + 1, is_dev, node.key))

        # Anything the lockfile lists but the walk never reached (optional or
        # platform-specific entries) still gets scanned, marked deep.
        for path, (pkg_name, entry) in by_path.items():
            if path not in seen:
                graph.add(
                    ResolvedPackage(
                        ecosystem=self.name,
                        name=pkg_name,
                        version=str(entry["version"]),
                        depth=99,
                        is_dev=bool(entry.get("dev")),
                        integrity=entry.get("integrity"),
                        resolved_url=entry.get("resolved"),
                        raw={**_npm_extras(entry), "unreachable": True},
                    )
                )
        return graph

    # ---- lockfileVersion 1 -------------------------------------------------
    def _parse_lock_v1(self, data: dict, filename: str) -> DependencyGraph:
        graph = DependencyGraph(ecosystem=self.name, manifest_filename=filename)

        def walk(deps: dict, depth: int, parent_key: str | None) -> None:
            for pkg_name, entry in (deps or {}).items():
                if not isinstance(entry, dict) or "version" not in entry:
                    continue
                node = graph.add(
                    ResolvedPackage(
                        ecosystem=self.name,
                        name=pkg_name,
                        version=str(entry["version"]),
                        depth=depth,
                        is_direct=depth == 0,
                        is_dev=bool(entry.get("dev")),
                        parents=(parent_key,) if parent_key else (),
                        integrity=entry.get("integrity"),
                        resolved_url=entry.get("resolved"),
                        raw=_npm_extras(entry),
                    )
                )
                if parent_key:
                    graph.link(parent_key, node.key)
                if depth == 0:
                    graph.direct_names.add(pkg_name)
                walk(entry.get("dependencies") or {}, depth + 1, node.key)

        walk(data.get("dependencies") or {}, 0, None)
        graph.warnings.append(
            "lockfileVersion 1 nests by hoisting; dependency depth is approximate."
        )
        return graph

    # ---- yarn.lock (classic v1) -------------------------------------------
    _YARN_ENTRY = re.compile(r'^((?:"[^"]+"|[^\s:][^:]*?)(?:,\s*(?:"[^"]+"|[^:]+))*):\s*$')

    def _parse_yarn_lock(self, content: str, filename: str) -> DependencyGraph:
        graph = DependencyGraph(ecosystem=self.name, manifest_filename=filename)
        if "__metadata:" in content:
            graph.warnings.append(
                "yarn berry lockfile detected; parsed with the classic reader."
            )
        current: list[str] | None = None
        version: str | None = None

        def flush() -> None:
            nonlocal current, version
            if current and version:
                for spec in current:
                    pkg_name = _yarn_name(spec)
                    if pkg_name:
                        graph.add(
                            ResolvedPackage(
                                ecosystem=self.name,
                                name=pkg_name,
                                version=version,
                                depth=0,
                                is_direct=True,
                                raw={"from_yarn_lock": True},
                            )
                        )
                        graph.direct_names.add(pkg_name)
                        break
            current, version = None, None

        for line in content.splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if not line.startswith(" ") and line.rstrip().endswith(":"):
                flush()
                current = [s.strip().strip('"') for s in line.rstrip()[:-1].split(",")]
            elif current is not None:
                stripped = line.strip()
                if stripped.startswith("version"):
                    version = stripped.split(None, 1)[1].strip().strip('"')
        flush()
        graph.warnings.append(
            "yarn.lock does not record the dependency tree shape; all packages "
            "are reported at depth 0."
        )
        return graph

    # -- registry -----------------------------------------------------------
    async def fetch_metadata(self, name: str, http: HttpClient) -> PackageMetadata:
        # The abbreviated document omits `time` and `maintainers`, which the
        # malicious-package heuristics need, so request the full document.
        data = await http.get_json(f"{REGISTRY}/{_encode(name)}", ttl=86_400)
        if data is None:
            return PackageMetadata(ecosystem=self.name, name=name, exists=False)

        dist_tags = data.get("dist-tags") or {}
        latest = dist_tags.get("latest")
        versions: dict[str, Any] = data.get("versions") or {}
        latest_doc = versions.get(latest, {}) if latest else {}

        times = data.get("time") or {}
        published: dict[str, datetime] = {}
        for key, value in times.items():
            if key in ("created", "modified"):
                continue
            parsed = parse_iso(value)
            if parsed:
                published[key] = parsed

        repo = latest_doc.get("repository") or data.get("repository")
        repo_url = _repo_url(repo)
        readme = data.get("readme") or ""
        if readme.strip().lower() in ("erroneous metadata", "no readme data"):
            readme = ""

        scripts = latest_doc.get("scripts") or {}
        install_scripts = {k: v for k, v in scripts.items() if k in INSTALL_HOOKS}

        return PackageMetadata(
            ecosystem=self.name,
            name=data.get("name", name),
            exists=True,
            latest_version=latest,
            description=data.get("description") or latest_doc.get("description"),
            repository_url=repo_url,
            homepage=data.get("homepage"),
            license=_license(latest_doc.get("license") or data.get("license")),
            first_published=parse_iso(times.get("created")),
            last_published=parse_iso(times.get("modified")),
            version_published=published,
            maintainers=[
                m.get("name", "") if isinstance(m, dict) else str(m)
                for m in (data.get("maintainers") or [])
            ],
            has_readme=bool(readme.strip()),
            readme_length=len(readme),
            install_scripts=install_scripts,
            deprecated=bool(latest_doc.get("deprecated") or data.get("deprecated")),
            raw={
                "versions": sorted(versions),
                "dist_tags": dist_tags,
                "has_dist_files": bool(latest_doc.get("dist")),
            },
        )

    async def namespace_is_claimed(self, scope: str, http: HttpClient) -> bool | None:
        """Check whether an npm @scope is in use on the public registry.

        npm exposes no "does this org exist" endpoint without authentication.
        The registry search API is fuzzy — it happily returns unrelated matches
        for a nonexistent scope — so the reliable signal is not the result
        count but whether any returned package name actually sits under the
        scope. Heuristic, and reported as such.
        """
        if not scope.startswith("@"):
            scope = f"@{scope}"
        prefix = f"{scope.lower()}/"
        try:
            data = await http.get_json(
                SEARCH_API, params={"text": prefix, "size": "20"}, ttl=86_400
            )
        except Exception:
            return None
        objects = (data or {}).get("objects") or []
        if not objects:
            return None
        return any(
            (o.get("package") or {}).get("name", "").lower().startswith(prefix)
            for o in objects
        )

    async def fetch_download_count(self, name: str, http: HttpClient) -> int | None:
        data = await http.get_json(f"{DOWNLOADS_API}/{_encode(name)}", ttl=86_400)
        if not data:
            return None
        value = data.get("downloads")
        return int(value) if isinstance(value, int | float) else None


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _encode(name: str) -> str:
    """npm scoped names are URL-encoded as %2f in the registry path."""
    return name.replace("/", "%2f")


def _name_from_path(path: str) -> str:
    marker = "node_modules/"
    idx = path.rfind(marker)
    return path[idx + len(marker) :] if idx != -1 else path


def _npm_extras(entry: dict) -> dict:
    extras: dict[str, Any] = {}
    scripts = entry.get("scripts") or {}
    hooks = {k: v for k, v in scripts.items() if k in INSTALL_HOOKS}
    if hooks:
        extras["install_scripts"] = hooks
    if entry.get("hasInstallScript"):
        extras["has_install_script"] = True
    if entry.get("optional"):
        extras["optional"] = True
    return extras


def _strip_range(spec: str) -> str:
    """Best-effort concrete version from a semver range, for display only."""
    if spec.startswith(("npm:", "file:", "link:", "git+", "github:", "workspace:")):
        return spec
    match = re.search(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", spec)
    return match.group(0) if match else spec.lstrip("^~>=< v")


def _yarn_name(spec: str) -> str | None:
    """`@babel/core@^7.0.0` -> `@babel/core`; `express@^4` -> `express`."""
    spec = spec.strip().strip('"')
    if spec.startswith("@"):
        idx = spec.find("@", 1)
        return spec[:idx] if idx != -1 else spec
    idx = spec.find("@")
    return spec[:idx] if idx > 0 else (spec or None)


def _repo_url(repo: Any) -> str | None:
    if isinstance(repo, str):
        url = repo
    elif isinstance(repo, dict):
        url = repo.get("url") or ""
    else:
        return None
    if not url:
        return None
    url = re.sub(r"^git\+", "", url)
    url = re.sub(r"\.git$", "", url)
    url = url.replace("git://", "https://").replace("git@github.com:", "https://github.com/")
    if url.startswith("github:"):
        url = "https://github.com/" + url[len("github:") :]
    elif re.fullmatch(r"[\w.-]+/[\w.-]+", url):
        url = "https://github.com/" + url
    return url


def _license(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return value.get("type")
    if isinstance(value, list) and value:
        return _license(value[0])
    return None
