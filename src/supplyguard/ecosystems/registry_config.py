"""Parsers for package-manager registry configuration.

Dependency confusion is fundamentally a *resolution* bug: the package manager
was told to look in two places and chose the wrong one. That intent lives in
`.npmrc`, `pip.conf`, `.yarnrc.yml` and friends, so the dependency-confusion
detector reads them rather than guessing which names are internal.
"""

from __future__ import annotations

import configparser
import io
import re
from dataclasses import dataclass, field

#: Registries that are the public default for their ecosystem.
PUBLIC_REGISTRIES = (
    "registry.npmjs.org",
    "registry.yarnpkg.com",
    "pypi.org",
    "files.pythonhosted.org",
    "rubygems.org",
    "repo1.maven.org",
    "repo.maven.apache.org",
    "search.maven.org",
    "central.sonatype.com",
)


@dataclass(slots=True)
class RegistryConfig:
    """What a package manager was told about where to fetch packages from."""

    filename: str
    #: Scope/namespace -> registry URL (npm `@scope:registry=`, yarn npmScopes).
    scoped_registries: dict[str, str] = field(default_factory=dict)
    #: The default registry, when overridden.
    default_registry: str | None = None
    #: Additional indexes consulted *alongside* the default. This is the pip
    #: dependency-confusion vector: pip queries every index and takes the
    #: highest version, regardless of which index it came from.
    extra_indexes: list[str] = field(default_factory=list)
    #: True when an auth token is configured, implying a real private registry.
    has_credentials: bool = False
    warnings: list[str] = field(default_factory=list)

    @property
    def private_scopes(self) -> set[str]:
        """Scopes pointed at something other than the public registry."""
        return {
            scope
            for scope, url in self.scoped_registries.items()
            if not is_public_registry(url)
        }

    @property
    def private_registries(self) -> set[str]:
        urls = set(self.scoped_registries.values()) | set(self.extra_indexes)
        if self.default_registry:
            urls.add(self.default_registry)
        return {u for u in urls if not is_public_registry(u)}


def is_public_registry(url: str | None) -> bool:
    if not url:
        return False
    return any(host in url for host in PUBLIC_REGISTRIES)


def parse_npmrc(content: str, filename: str = ".npmrc") -> RegistryConfig:
    """Parse an `.npmrc`.

    Lines of interest:
        registry=https://...              default registry
        @acme:registry=https://...        scoped registry
        //host/:_authToken=...            credentials for a host
    """
    config = RegistryConfig(filename=filename)
    for raw in content.splitlines():
        line = raw.split("#", 1)[0].split(";", 1)[0].strip()
        if not line or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip('"')
        if key.startswith("//"):
            if "_authToken" in key or "_auth" in key or "username" in key:
                config.has_credentials = True
            continue
        if key == "registry":
            config.default_registry = value
        elif key.endswith(":registry") and key.startswith("@"):
            config.scoped_registries[key[: -len(":registry")].lower()] = value
    return config


def parse_yarnrc_yml(content: str, filename: str = ".yarnrc.yml") -> RegistryConfig:
    """Parse a Yarn Berry `.yarnrc.yml` for scope-to-registry mappings."""
    config = RegistryConfig(filename=filename)
    try:
        import yaml

        data = yaml.safe_load(content) or {}
    except Exception as exc:
        config.warnings.append(f"Could not parse {filename}: {exc}")
        return config
    if not isinstance(data, dict):
        return config

    default = data.get("npmRegistryServer")
    if isinstance(default, str):
        config.default_registry = default
    for scope, settings in (data.get("npmScopes") or {}).items():
        if isinstance(settings, dict):
            url = settings.get("npmRegistryServer") or settings.get("npmPublishRegistry")
            if isinstance(url, str):
                config.scoped_registries[f"@{scope}".lower()] = url
            if settings.get("npmAuthToken") or settings.get("npmAuthIdent"):
                config.has_credentials = True
    if data.get("npmAuthToken"):
        config.has_credentials = True
    return config


def parse_pip_conf(content: str, filename: str = "pip.conf") -> RegistryConfig:
    """Parse a `pip.conf` / `pip.ini`.

    `extra-index-url` is the important one. pip does not treat indexes as a
    priority list: it queries all of them and installs the highest version it
    finds anywhere. A public index listed alongside a private one is therefore
    a standing dependency-confusion exposure, which is precisely the mechanism
    Alex Birsan used in 2021.
    """
    config = RegistryConfig(filename=filename)
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read_file(io.StringIO(content))
    except configparser.Error as exc:
        config.warnings.append(f"Could not parse {filename}: {exc}")
        return config

    for section in parser.sections():
        for key, value in parser.items(section):
            normalised = key.replace("_", "-").strip().lower()
            if normalised == "index-url":
                config.default_registry = value.strip()
                if _has_inline_credentials(value):
                    config.has_credentials = True
            elif normalised == "extra-index-url":
                for url in value.split():
                    config.extra_indexes.append(url.strip())
                    if _has_inline_credentials(url):
                        config.has_credentials = True
    return config


def parse_gemrc(content: str, filename: str = ".gemrc") -> RegistryConfig:
    config = RegistryConfig(filename=filename)
    try:
        import yaml

        data = yaml.safe_load(content) or {}
    except Exception as exc:
        config.warnings.append(f"Could not parse {filename}: {exc}")
        return config
    if isinstance(data, dict):
        sources = data.get(":sources") or data.get("sources")
        if isinstance(sources, list):
            for url in sources:
                if isinstance(url, str) and not is_public_registry(url):
                    config.extra_indexes.append(url)
    return config


def parse_maven_settings(content: str, filename: str = "settings.xml") -> RegistryConfig:
    """Extract mirror and repository URLs from a Maven `settings.xml`."""
    from xml.etree import ElementTree

    config = RegistryConfig(filename=filename)
    try:
        root = ElementTree.fromstring(content.encode())
    except ElementTree.ParseError as exc:
        config.warnings.append(f"Could not parse {filename}: {exc}")
        return config
    for element in root.iter():
        tag = element.tag.rsplit("}", 1)[-1]
        if tag == "url" and element.text:
            url = element.text.strip()
            if not is_public_registry(url):
                config.extra_indexes.append(url)
        elif tag in ("username", "password") and element.text:
            config.has_credentials = True
    return config


_PARSERS = {
    ".npmrc": parse_npmrc,
    ".yarnrc": parse_npmrc,  # classic .yarnrc uses the same key=value shape
    ".yarnrc.yml": parse_yarnrc_yml,
    "pip.conf": parse_pip_conf,
    "pip.ini": parse_pip_conf,
    ".gemrc": parse_gemrc,
    "settings.xml": parse_maven_settings,
}


def parse_registry_config(filename: str, content: str) -> RegistryConfig | None:
    """Dispatch to the parser for a known registry config filename."""
    base = filename.rsplit("/", 1)[-1]
    parser = _PARSERS.get(base)
    if parser is None:
        return None
    return parser(content, base)


def _has_inline_credentials(url: str) -> bool:
    """`https://user:token@host/simple` — credentials embedded in the URL."""
    return bool(re.match(r"^https?://[^/@\s]+:[^/@\s]+@", url.strip()))
