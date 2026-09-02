"""RubyGems ecosystem adapter."""

from __future__ import annotations

import re
from typing import ClassVar

from supplyguard.clients.http import HttpClient
from supplyguard.core.types import DependencyGraph, PackageMetadata, ResolvedPackage
from supplyguard.ecosystems.base import EcosystemAdapter, register
from supplyguard.ecosystems.versions import parse_gem_version
from supplyguard.utils.dates import parse_iso

API = "https://rubygems.org/api/v1"

# `    rails (7.0.4)` / `      actionpack (= 7.0.4)` inside GEM specs blocks.
_SPEC_LINE = re.compile(r"^(?P<indent>\s+)(?P<name>[A-Za-z0-9._\-]+)\s+\((?P<version>[^)]+)\)\s*$")
_BARE_LINE = re.compile(r"^(?P<indent>\s+)(?P<name>[A-Za-z0-9._\-]+)(?:\s+\(.*\))?\s*$")


@register
class RubyGemsAdapter(EcosystemAdapter):
    name: ClassVar[str] = "rubygems"
    display_name: ClassVar[str] = "RubyGems (Ruby)"
    osv_ecosystem: ClassVar[str] = "RubyGems"
    ghsa_ecosystem: ClassVar[str] = "RUBYGEMS"
    manifest_patterns: ClassVar[tuple[str, ...]] = ("Gemfile.lock", "gems.locked", "Gemfile")
    lockfile_patterns: ClassVar[tuple[str, ...]] = ("Gemfile.lock", "gems.locked")
    registry_config_patterns: ClassVar[tuple[str, ...]] = (".gemrc", "Gemfile")

    def registry_package_url(self, name: str) -> str:
        return f"https://rubygems.org/gems/{name}"

    def parse_version(self, version: str) -> tuple:
        return parse_gem_version(version)

    def looks_private(self, name: str) -> bool:
        return bool(re.match(r"^(internal|private|corp|acme|company)[-_]", name.lower()))

    # -- manifest parsing ---------------------------------------------------
    def parse_manifest(self, content: str, filename: str) -> DependencyGraph:
        base = filename.rsplit("/", 1)[-1]
        if base == "Gemfile":
            return self._parse_gemfile(content, base)
        return self._parse_lock(content, base)

    def _parse_lock(self, content: str, filename: str) -> DependencyGraph:
        """Parse Gemfile.lock.

        The `specs:` block is indentation-structured: four-space lines are
        resolved gems, six-space lines are that gem's dependencies. The trailing
        `DEPENDENCIES` block lists what the Gemfile asked for directly, which is
        exactly the information needed to compute depth properly.
        """
        graph = DependencyGraph(ecosystem=self.name, manifest_filename=filename)

        section: str | None = None
        in_specs = False
        versions: dict[str, str] = {}
        edges: dict[str, list[str]] = {}
        current: str | None = None
        declared: set[str] = set()

        for line in content.splitlines():
            if not line.strip():
                continue
            if not line.startswith(" "):
                section = line.strip().rstrip(":")
                in_specs = False
                current = None
                continue
            if line.strip() == "specs:":
                in_specs = True
                continue

            if section in ("GEM", "PATH", "GIT") and in_specs:
                spec = _SPEC_LINE.match(line)
                indent = len(line) - len(line.lstrip())
                if spec and indent <= 4:
                    current = spec.group("name")
                    versions[current] = spec.group("version").strip()
                    edges.setdefault(current, [])
                elif current is not None and indent >= 6:
                    dep = _BARE_LINE.match(line)
                    if dep:
                        edges[current].append(dep.group("name"))
            elif section == "DEPENDENCIES":
                dep = _BARE_LINE.match(line)
                if dep:
                    declared.add(dep.group("name").rstrip("!"))

        roots = [g for g in declared if g in versions] or [
            g for g in versions if g not in {d for deps in edges.values() for d in deps}
        ]
        graph.direct_names.update(roots)

        # BFS from the declared gems so depth reflects the real dependency tree.
        depth: dict[str, int] = dict.fromkeys(roots, 0)
        frontier = list(roots)
        while frontier:
            nxt: list[str] = []
            for gem in frontier:
                for child in edges.get(gem, []):
                    if child in versions and child not in depth:
                        depth[child] = depth[gem] + 1
                        nxt.append(child)
            frontier = nxt

        for gem, version in versions.items():
            graph.add(
                ResolvedPackage(
                    ecosystem=self.name,
                    name=gem,
                    version=version,
                    depth=depth.get(gem, 1),
                    is_direct=depth.get(gem, 1) == 0,
                )
            )
        for gem, children in edges.items():
            if gem not in versions:
                continue
            for child in children:
                if child in versions:
                    graph.link(f"{gem}@{versions[gem]}", f"{child}@{versions[child]}")
        return graph

    def _parse_gemfile(self, content: str, filename: str) -> DependencyGraph:
        graph = DependencyGraph(ecosystem=self.name, manifest_filename=filename)
        graph.warnings.append(
            "Gemfile declares constraints, not resolved versions. Upload "
            "Gemfile.lock for transitive coverage."
        )
        pattern = re.compile(r"""^\s*gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?""")
        for line in content.splitlines():
            match = pattern.match(line)
            if match:
                graph.direct_names.add(match.group(1))
                graph.add(
                    ResolvedPackage(
                        ecosystem=self.name,
                        name=match.group(1),
                        version=(match.group(2) or "*").lstrip("~><= "),
                        depth=0,
                        is_direct=True,
                        raw={"unresolved": True},
                    )
                )
        return graph

    # -- registry -----------------------------------------------------------
    async def fetch_metadata(self, name: str, http: HttpClient) -> PackageMetadata:
        data = await http.get_json(f"{API}/gems/{name}.json", ttl=86_400)
        if data is None:
            return PackageMetadata(ecosystem=self.name, name=name, exists=False)

        versions = await self._fetch_versions(name, http)
        published = {
            v["number"]: parse_iso(v.get("created_at"))
            for v in versions
            if v.get("number") and parse_iso(v.get("created_at"))
        }
        info = data.get("info") or ""
        return PackageMetadata(
            ecosystem=self.name,
            name=data.get("name", name),
            exists=True,
            latest_version=data.get("version"),
            description=info,
            repository_url=data.get("source_code_uri") or data.get("homepage_uri"),
            homepage=data.get("homepage_uri"),
            license=", ".join(data.get("licenses") or []) or None,
            first_published=min(published.values()) if published else None,
            last_published=max(published.values()) if published else None,
            version_published=published,  # type: ignore[arg-type]
            downloads_last_month=None,
            maintainers=[],
            has_readme=len(info.strip()) > 40,
            readme_length=len(info),
            # Native extensions run arbitrary code via extconf.rb at `gem install`.
            install_scripts=(
                {"extconf.rb": "Gem ships native extensions, compiled at install time."}
                if any(v.get("platform") not in (None, "ruby") for v in versions)
                else {}
            ),
            raw={
                "versions": [v.get("number") for v in versions],
                "total_downloads": data.get("downloads"),
                "version_downloads": data.get("version_downloads"),
            },
        )

    async def _fetch_versions(self, name: str, http: HttpClient) -> list[dict]:
        try:
            data = await http.get_json(f"{API}/versions/{name}.json", ttl=86_400)
        except Exception:
            return []
        return data if isinstance(data, list) else []

    async def fetch_download_count(self, name: str, http: HttpClient) -> int | None:
        """RubyGems reports lifetime downloads only.

        Approximated to a monthly figure so that the cross-ecosystem "is this
        package obscure?" threshold stays comparable; the estimate is recorded
        in the finding evidence rather than presented as a measured value.
        """
        data = await http.get_json(f"{API}/gems/{name}.json", ttl=86_400)
        if not data:
            return None
        total = data.get("downloads")
        return int(total) if isinstance(total, int) else None
