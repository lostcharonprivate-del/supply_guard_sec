"""Dependency confusion detection.

The attack, as Alex Birsan demonstrated in 2021: a build resolves a package
name from more than one source, and the *public* registry wins. Publishing a
package under an internal name — or under an unclaimed namespace — is then
enough to get code executed inside a build that believed it was pulling a
private dependency. The 2022 PyTorch `torchtriton` compromise was the same
mechanism against a nightly build's `extra-index-url`.

Remediation differs fundamentally from typosquatting — you claim the name or
fix your resolver configuration rather than correcting a spelling — which is
why this is a separate finding category.
"""

from __future__ import annotations

import re
from typing import ClassVar

from supplyguard.core.types import (
    Evidence,
    Finding,
    FindingCategory,
    ResolvedPackage,
    Severity,
)
from supplyguard.detectors.base import Detector, ScanContext, register_detector
from supplyguard.ecosystems.registry_config import (
    RegistryConfig,
    is_public_registry,
    parse_registry_config,
)

#: Name fragments that suggest a package was never meant to be public.
_INTERNAL_HINTS = re.compile(
    r"(^|[-_.@/])(internal|private|corp|corporate|intranet|inhouse|in-house"
    r"|confidential|secret|staging|sandbox|proprietary)([-_./]|$)",
    re.IGNORECASE,
)


@register_detector
class DependencyConfusionDetector(Detector):
    name: ClassVar[str] = "dependency_confusion"
    category: ClassVar[FindingCategory] = FindingCategory.DEPENDENCY_CONFUSION
    description: ClassVar[str] = (
        "Identifies packages your build intends to resolve privately, then "
        "checks whether the public registry can satisfy the same name — and "
        "whether your private namespaces are reserved publicly, since an "
        "unclaimed namespace is squattable."
    )
    known_false_positives: ClassVar[tuple[str, ...]] = (
        "A company that deliberately mirrors its own package publicly will be "
        "flagged; the tool cannot tell an intentional public release from a "
        "shadowing one.",
        "Name-convention heuristics ('acme-*' looks internal) misfire on "
        "projects whose public packages share that prefix. Configure the "
        "organisation scopes explicitly to remove the guesswork.",
    )
    known_false_negatives: ClassVar[tuple[str, ...]] = (
        "Without a registry config file, internal packages that follow no "
        "naming convention are indistinguishable from public ones.",
        "Resolution order also depends on CI environment variables and CLI "
        "flags that are not visible in the uploaded files.",
        "A public package published *after* the scan closes the window; this "
        "is a point-in-time check, not monitoring.",
    )

    async def detect(self, ctx: ScanContext) -> list[Finding]:
        configs = self._parse_configs(ctx)
        findings: list[Finding] = []

        findings.extend(self._check_resolver_configuration(ctx, configs))
        findings.extend(await self._check_unclaimed_namespaces(ctx, configs))
        findings.extend(await self._check_public_shadowing(ctx, configs))
        return findings

    # -- inputs -------------------------------------------------------------
    def _parse_configs(self, ctx: ScanContext) -> list[RegistryConfig]:
        configs: list[RegistryConfig] = []
        for filename, content in ctx.registry_configs.items():
            parsed = parse_registry_config(filename, content)
            if parsed is None:
                continue
            ctx.notes.extend(parsed.warnings)
            configs.append(parsed)
        return configs

    def _private_scopes(self, ctx: ScanContext, configs: list[RegistryConfig]) -> set[str]:
        scopes = {s.lower() for c in configs for s in c.private_scopes}
        scopes.update(s.lower() for s in ctx.config.organization_scopes)
        return scopes

    def _is_internal_name(
        self, ctx: ScanContext, package: ResolvedPackage, private_scopes: set[str]
    ) -> tuple[bool, str] | tuple[bool, None]:
        """Decide whether a package was *meant* to be private, and say why."""
        name = package.name
        scope = ctx.adapter.scope_of(name)
        if scope and scope.lower() in private_scopes:
            return True, f"its namespace '{scope}' is mapped to a private registry"
        for pattern in ctx.config.internal_name_patterns:
            if re.search(pattern, name, re.IGNORECASE):
                return True, f"it matches the configured internal pattern '{pattern}'"
        if _INTERNAL_HINTS.search(name):
            return True, "its name contains an internal-only marker"
        if ctx.adapter.looks_private(name) and not scope:
            return True, "its name follows an internal naming convention"
        return False, None

    # -- 1. resolver configuration ------------------------------------------
    def _check_resolver_configuration(
        self, ctx: ScanContext, configs: list[RegistryConfig]
    ) -> list[Finding]:
        """Flag configurations that structurally permit confusion.

        This finding is about the *mechanism*, not any specific package: it is
        present even when nothing is currently being shadowed, and it is the
        one worth fixing first because it closes the whole class.
        """
        findings: list[Finding] = []
        for config in configs:
            private = config.private_registries
            public_alongside = [u for u in config.extra_indexes if is_public_registry(u)]
            if not private or not public_alongside:
                continue

            findings.append(
                Finding(
                    category=self.category,
                    severity=Severity.HIGH,
                    title=f"{config.filename} queries a public index alongside a private one",
                    description=(
                        f"{config.filename} configures both a private registry "
                        f"({', '.join(sorted(private))}) and a public index "
                        f"({', '.join(public_alongside)}). Package managers that "
                        "consult every configured index — pip in particular — select "
                        "the highest version found across all of them rather than "
                        "preferring the private one. Anyone who publishes a higher "
                        "version of one of your internal package names publicly wins "
                        "resolution. This is the mechanism behind the 2022 PyTorch "
                        "`torchtriton` compromise."
                    ),
                    ecosystem=ctx.adapter.name,
                    identifier=f"DEPCONF-CONFIG-{config.filename}",
                    remediation=(
                        "Do not mix indexes. Point the resolver at a single private "
                        "registry that proxies the public one, so the private index "
                        "always wins; for pip, replace `extra-index-url` with an "
                        "`index-url` pointing at your proxy. Where the tooling "
                        "supports it, pin internal packages to the private source "
                        "explicitly."
                    ),
                    evidence=[
                        Evidence("Private registry", ", ".join(sorted(private)), 0.5),
                        Evidence("Public index also consulted", ", ".join(public_alongside), 0.5),
                        Evidence(
                            "Credentials configured",
                            "Yes — this is a real private registry, not a placeholder."
                            if config.has_credentials
                            else "No credentials found in this file.",
                        ),
                    ],
                    confidence=0.9,
                    is_direct=True,
                    metadata={"config_file": config.filename},
                )
            )
        return findings

    # -- 2. unclaimed namespaces --------------------------------------------
    async def _check_unclaimed_namespaces(
        self, ctx: ScanContext, configs: list[RegistryConfig]
    ) -> list[Finding]:
        if not ctx.adapter.supports_scopes:
            return []
        # Only namespaces the project actually routes privately are checked.
        # Probing every scope in the tree would burn API calls confirming that
        # @babel and @types are, unsurprisingly, claimed.
        scopes = self._private_scopes(ctx, configs)
        findings: list[Finding] = []
        for scope in sorted(scopes):
            claimed = await ctx.adapter.namespace_is_claimed(scope, ctx.http)
            if claimed is not False:
                # True (safe) or None (undeterminable) — do not guess.
                if claimed is None:
                    ctx.notes.append(
                        f"Could not determine whether the namespace '{scope}' is "
                        "reserved on the public registry."
                    )
                continue
            findings.append(
                Finding(
                    category=self.category,
                    severity=Severity.HIGH,
                    title=f"Private namespace '{scope}' is not reserved publicly",
                    description=(
                        f"Your configuration routes '{scope}' to a private registry, "
                        "but no package under that namespace exists on the public "
                        "registry. The namespace is therefore unclaimed and anyone "
                        f"can register it. Once they do, any resolver that falls back "
                        "to the public registry — a misconfigured developer machine, "
                        "a CI job without your registry credentials — will install "
                        "their code instead of yours."
                    ),
                    ecosystem=ctx.adapter.name,
                    identifier=f"DEPCONF-SCOPE-{scope}",
                    remediation=(
                        f"Reserve '{scope}' on the public registry now: create the "
                        "organisation and publish a placeholder package under it. "
                        "This costs nothing and permanently removes the attack."
                    ),
                    references=[ctx.adapter.registry_package_url(f"{scope}/placeholder")],
                    evidence=[
                        Evidence(
                            "Namespace status",
                            f"No public packages found under '{scope}'.",
                            0.8,
                        ),
                        Evidence(
                            "Private routing",
                            f"'{scope}' is mapped to a private registry in your config.",
                            0.6,
                        ),
                    ],
                    confidence=0.75,
                    is_direct=True,
                    metadata={"scope": scope},
                )
            )
        return findings

    # -- 3. public shadowing of internal names -------------------------------
    async def _check_public_shadowing(
        self, ctx: ScanContext, configs: list[RegistryConfig]
    ) -> list[Finding]:
        private_scopes = self._private_scopes(ctx, configs)
        internal: list[tuple[ResolvedPackage, str]] = []
        seen: set[str] = set()
        for package in ctx.packages:
            key = ctx.adapter.normalize_name(package.name)
            if key in seen:
                continue
            is_internal, reason = self._is_internal_name(ctx, package, private_scopes)
            if is_internal and reason:
                seen.add(key)
                internal.append((package, reason))

        if not internal:
            return []

        metadata = await ctx.metadata.get_many([p.name for p, _ in internal])
        findings: list[Finding] = []
        for package, reason in internal:
            meta = metadata.get(ctx.adapter.normalize_name(package.name))
            if meta is None or not meta.exists:
                # The safe outcome: nothing public answers to this name.
                continue

            same_version = (
                package.version in meta.version_published
                if meta.version_published
                else None
            )
            findings.append(
                Finding(
                    category=self.category,
                    severity=Severity.CRITICAL if package.is_direct else Severity.HIGH,
                    title=f"Internal package '{package.name}' also exists on the public registry",
                    description=(
                        f"'{package.name}' appears to be an internal dependency — "
                        f"{reason} — yet a package with exactly that name is published "
                        "on the public registry. If any resolver consults the public "
                        "registry for this name, it may install the public package "
                        "instead of yours, executing code you do not control."
                    ),
                    package_name=package.name,
                    package_version=package.version,
                    ecosystem=ctx.adapter.name,
                    identifier=f"DEPCONF-{package.name}",
                    remediation=(
                        f"Verify who owns the public '{package.name}'. If it is not "
                        "you, treat this as an active incident: audit builds that may "
                        "have resolved it, then either rename the internal package or "
                        "claim the public name. Pin the package to your private "
                        "registry explicitly so resolution cannot drift."
                    ),
                    references=[ctx.adapter.registry_package_url(package.name)],
                    evidence=[
                        Evidence("Why this looks internal", reason.capitalize(), 0.7),
                        Evidence(
                            "Public registry",
                            f"A public package named '{package.name}' exists"
                            + (
                                f", latest version {meta.latest_version}."
                                if meta.latest_version
                                else "."
                            ),
                            0.9,
                        ),
                        Evidence(
                            "Version overlap",
                            f"The public package also publishes version "
                            f"{package.version}, so resolution could silently "
                            "substitute it."
                            if same_version
                            else "The public package does not publish the exact "
                            "version you resolved, so a substitution would be visible "
                            "as a version change.",
                            0.6 if same_version else 0.2,
                        ),
                        Evidence(
                            "Public maintainers",
                            ", ".join(meta.maintainers[:5]) or "not disclosed",
                        ),
                    ],
                    confidence=0.85 if same_version else 0.7,
                    depth=package.depth,
                    is_direct=package.is_direct,
                    metadata={
                        "public_latest_version": meta.latest_version,
                        "version_overlap": same_version,
                        "reason": reason,
                    },
                )
            )
        return findings
