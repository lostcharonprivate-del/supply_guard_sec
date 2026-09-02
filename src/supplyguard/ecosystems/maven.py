"""Maven Central ecosystem adapter."""

from __future__ import annotations

import re
from typing import Any, ClassVar
from xml.etree import ElementTree

from supplyguard.clients.http import HttpClient
from supplyguard.core.types import DependencyGraph, PackageMetadata, ResolvedPackage
from supplyguard.ecosystems.base import EcosystemAdapter, ManifestParseError, register
from supplyguard.ecosystems.versions import parse_maven_version
from supplyguard.utils.dates import parse_iso

SEARCH_API = "https://search.maven.org/solrsearch/select"
POM_BASE = "https://repo1.maven.org/maven2"

#: Scopes whose artifacts do not ship in the built application.
NON_RUNTIME_SCOPES = {"test", "provided"}


@register
class MavenAdapter(EcosystemAdapter):
    name: ClassVar[str] = "maven"
    display_name: ClassVar[str] = "Maven Central (Java)"
    osv_ecosystem: ClassVar[str] = "Maven"
    ghsa_ecosystem: ClassVar[str] = "MAVEN"
    manifest_patterns: ClassVar[tuple[str, ...]] = (
        "pom.xml",
        "gradle.lockfile",
        "*.gradle.lockfile",
    )
    lockfile_patterns: ClassVar[tuple[str, ...]] = ("gradle.lockfile", "*.gradle.lockfile")
    registry_config_patterns: ClassVar[tuple[str, ...]] = ("settings.xml", "build.gradle")
    #: A Maven coordinate's groupId *is* a namespace, and one that must be
    #: proven-owned (via DNS or GitHub) before Central will accept a publish.
    supports_scopes: ClassVar[bool] = True
    #: Maven Central publishes no download statistics at all.
    download_metric: ClassVar[str] = "none"

    # -- naming -------------------------------------------------------------
    def normalize_name(self, name: str) -> str:
        # Maven coordinates are `groupId:artifactId` and are case-sensitive,
        # but comparisons in this tool are consistently case-insensitive.
        return name.strip().lower()

    def scope_of(self, name: str) -> str | None:
        return name.split(":", 1)[0] if ":" in name else None

    def registry_package_url(self, name: str) -> str:
        group, _, artifact = name.partition(":")
        return f"https://central.sonatype.com/artifact/{group}/{artifact}"

    def parse_version(self, version: str) -> tuple:
        return parse_maven_version(version)

    def looks_private(self, name: str) -> bool:
        """Reverse-DNS groupIds under an internal-looking domain."""
        group = self.scope_of(name) or ""
        return bool(re.match(r"^(com|org|io|net)\.(internal|corp|acme|company|private)\b", group))

    # -- manifest parsing ---------------------------------------------------
    def parse_manifest(self, content: str, filename: str) -> DependencyGraph:
        base = filename.rsplit("/", 1)[-1]
        if base.endswith(".lockfile"):
            return self._parse_gradle_lockfile(content, base)
        return self._parse_pom(content, base)

    def _parse_pom(self, content: str, filename: str) -> DependencyGraph:
        """Parse pom.xml.

        A pom lists only declared dependencies: Maven resolves the transitive
        closure at build time from each dependency's own pom. That resolution is
        performed later by :mod:`supplyguard.scanner` for Maven projects, so the
        graph produced here is the direct layer.
        """
        try:
            root = ElementTree.fromstring(content.encode())
        except ElementTree.ParseError as exc:
            raise ManifestParseError(f"{filename} is not valid XML: {exc}") from exc

        graph = DependencyGraph(ecosystem=self.name, manifest_filename=filename)
        ns = _namespace(root)
        properties = {
            _localname(child.tag): (child.text or "").strip()
            for child in root.find(f"{ns}properties") or []
        }
        # `${project.version}` is the single most common property in a pom.
        project_version = _text(root, f"{ns}version")
        if project_version:
            properties.setdefault("project.version", project_version)

        managed: dict[str, str] = {}
        dep_mgmt = root.find(f"{ns}dependencyManagement/{ns}dependencies")
        for dep in dep_mgmt or []:
            coord, version, _ = _read_dependency(dep, ns, properties)
            if coord and version:
                managed[coord] = version

        found = False
        for dep in root.find(f"{ns}dependencies") or []:
            coord, version, scope = _read_dependency(dep, ns, properties)
            if not coord:
                continue
            found = True
            version = version or managed.get(coord)
            if not version:
                graph.warnings.append(
                    f"{coord}: version comes from a parent POM or BOM that was not "
                    "uploaded, so it could not be resolved."
                )
                continue
            graph.direct_names.add(coord)
            graph.add(
                ResolvedPackage(
                    ecosystem=self.name,
                    name=coord,
                    version=version,
                    depth=0,
                    is_direct=True,
                    is_dev=scope in NON_RUNTIME_SCOPES,
                    raw={"scope": scope},
                )
            )

        if not found and root.tag.endswith("project"):
            graph.warnings.append("pom.xml declares no dependencies.")
        graph.warnings.append(
            "pom.xml lists direct dependencies only; transitive artifacts are "
            "resolved from Maven Central during the scan."
        )
        return graph

    def _parse_gradle_lockfile(self, content: str, filename: str) -> DependencyGraph:
        """Parse a Gradle dependency lockfile (`group:artifact:version=configs`)."""
        graph = DependencyGraph(ecosystem=self.name, manifest_filename=filename)
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("empty="):
                continue
            coordinate, _, configurations = line.partition("=")
            parts = coordinate.split(":")
            if len(parts) != 3:
                continue
            group, artifact, version = parts
            is_test = all(
                "test" in c.lower() or "compileClasspath" not in c
                for c in configurations.split(",")
            ) and "test" in configurations.lower()
            graph.add(
                ResolvedPackage(
                    ecosystem=self.name,
                    name=f"{group}:{artifact}",
                    version=version,
                    depth=0,
                    is_direct=True,
                    is_dev=is_test,
                    raw={"configurations": configurations},
                )
            )
        graph.warnings.append(
            "Gradle lockfiles are flat; every artifact is reported as direct."
        )
        return graph

    # -- registry -----------------------------------------------------------
    async def fetch_metadata(self, name: str, http: HttpClient) -> PackageMetadata:
        group, _, artifact = name.partition(":")
        if not artifact:
            return PackageMetadata(ecosystem=self.name, name=name, exists=False)

        data = await http.get_json(
            SEARCH_API,
            params={"q": f'g:"{group}" AND a:"{artifact}"', "rows": "20", "core": "gav", "wt": "json"},
            ttl=86_400,
        )
        docs = ((data or {}).get("response") or {}).get("docs") or []
        if not docs:
            return PackageMetadata(ecosystem=self.name, name=name, exists=False)

        published: dict[str, Any] = {}
        for doc in docs:
            version, timestamp = doc.get("v"), doc.get("timestamp")
            if version and timestamp:
                # Maven Central reports epoch milliseconds.
                published[version] = parse_iso(
                    __import__("datetime").datetime.fromtimestamp(
                        timestamp / 1000, tz=__import__("datetime").UTC
                    )
                )
        latest = max(published, key=self.parse_version) if published else docs[0].get("v")

        return PackageMetadata(
            ecosystem=self.name,
            name=name,
            exists=True,
            latest_version=latest,
            description=None,
            repository_url=None,
            homepage=self.registry_package_url(name),
            first_published=min(published.values()) if published else None,
            last_published=max(published.values()) if published else None,
            version_published=published,
            has_readme=False,
            raw={
                "versions": sorted(published, key=self.parse_version),
                "group_id": group,
                "artifact_id": artifact,
                # Maven Central verifies groupId ownership before first publish,
                # which is why namespace squatting is rarer here than on npm.
                "namespace_verified": True,
            },
        )


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _namespace(root: ElementTree.Element) -> str:
    return root.tag[: root.tag.index("}") + 1] if "}" in root.tag else ""


def _localname(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _text(element: ElementTree.Element, path: str) -> str | None:
    found = element.find(path)
    return (found.text or "").strip() if found is not None and found.text else None


def _expand(value: str | None, properties: dict[str, str]) -> str | None:
    """Resolve `${property}` placeholders against the pom's own properties."""
    if not value:
        return value
    for _ in range(5):  # properties can reference other properties
        expanded = re.sub(
            r"\$\{([^}]+)\}", lambda m: properties.get(m.group(1), m.group(0)), value
        )
        if expanded == value:
            break
        value = expanded
    return None if "${" in value else value


def _read_dependency(
    dep: ElementTree.Element, ns: str, properties: dict[str, str]
) -> tuple[str | None, str | None, str]:
    group = _expand(_text(dep, f"{ns}groupId"), properties)
    artifact = _expand(_text(dep, f"{ns}artifactId"), properties)
    version = _expand(_text(dep, f"{ns}version"), properties)
    scope = (_text(dep, f"{ns}scope") or "compile").lower()
    if not group or not artifact:
        return None, None, scope
    return f"{group}:{artifact}", version, scope
