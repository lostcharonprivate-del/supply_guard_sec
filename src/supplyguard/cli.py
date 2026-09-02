"""SupplyGuard command line interface.

Runs a scan either fully locally (no server, no database, no Redis) or against
a running SupplyGuard API. The local path is the one to reach for first: it
makes the whole detection pipeline usable with a single command.
"""

from __future__ import annotations

import asyncio
import json as jsonlib
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from supplyguard.core.types import FindingCategory, SEVERITY_ORDER, Severity
from supplyguard.scanner import ScanRequest, ScanResult, Scanner

app = typer.Typer(
    name="supplyguard",
    help="Supply chain security analyzer for npm, PyPI, RubyGems and Maven.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
error_console = Console(stderr=True)

SEVERITY_STYLES: dict[str, str] = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}
CATEGORY_LABELS: dict[str, str] = {
    "vulnerability": "CVE",
    "malicious": "MALICIOUS",
    "typosquat": "TYPOSQUAT",
    "dependency_confusion": "DEP-CONFUSION",
    "ci_anomaly": "CI",
    "stale": "STALE",
}


@app.command()
def scan(
    paths: Annotated[
        list[Path] | None,
        typer.Argument(help="Manifest/lockfile paths, or a directory to search."),
    ] = None,
    repo: Annotated[
        str | None,
        typer.Option("--repo", "-r", help="GitHub repository (owner/repo or URL)."),
    ] = None,
    ecosystem: Annotated[
        list[str] | None,
        typer.Option("--ecosystem", "-e", help="Restrict to these ecosystems."),
    ] = None,
    detector: Annotated[
        list[str] | None,
        typer.Option("--detector", "-d", help="Run only these detectors."),
    ] = None,
    severity: Annotated[
        str, typer.Option("--severity", "-s", help="Minimum severity to display.")
    ] = "info",
    fail_on: Annotated[
        str | None,
        typer.Option("--fail-on", help="Exit non-zero if a finding at or above this severity exists."),
    ] = None,
    output_json: Annotated[
        bool, typer.Option("--json", help="Emit machine-readable JSON instead of a report.")
    ] = False,
    show_tree: Annotated[
        bool, typer.Option("--tree", help="Show the dependency tree with findings overlaid.")
    ] = False,
    offline: Annotated[
        bool, typer.Option("--offline", help="Skip every detector that needs network access.")
    ] = False,
    api_url: Annotated[
        str | None,
        typer.Option("--api-url", help="Submit to a running SupplyGuard API instead of scanning locally."),
    ] = None,
    token: Annotated[
        str | None, typer.Option("--github-token", envvar="GITHUB_TOKEN", help="GitHub API token.")
    ] = None,
    redis_url: Annotated[
        str | None,
        typer.Option("--redis-url", envvar="REDIS_URL", help="Redis URL for the response cache."),
    ] = None,
) -> None:
    """Scan manifests for supply chain risk."""
    if not paths and not repo:
        error_console.print("[red]Provide a path to scan, or --repo owner/repo.[/red]")
        raise typer.Exit(2)

    minimum = _parse_severity(severity)
    threshold = _parse_severity(fail_on) if fail_on else None

    files = _collect_files(paths or [])
    if not files and not repo:
        error_console.print("[red]No supported manifest files found.[/red]")
        raise typer.Exit(2)

    if api_url:
        result_dict = asyncio.run(_scan_via_api(api_url, files, repo))
        _render_api_result(result_dict, output_json)
        raise typer.Exit(0)

    result = asyncio.run(
        _run_scan(files, repo, ecosystem, detector, offline, token, redis_url)
    )

    if output_json:
        console.print_json(jsonlib.dumps(_result_to_dict(result)))
    else:
        _render(result, minimum, show_tree)

    if result.errors and not result.findings:
        raise typer.Exit(1)
    if threshold is not None:
        limit = SEVERITY_ORDER.index(threshold)
        if any(SEVERITY_ORDER.index(f.severity) <= limit for f in result.findings):
            error_console.print(
                f"\n[red]Failing: findings at or above '{threshold.value}' severity.[/red]"
            )
            raise typer.Exit(1)
    raise typer.Exit(0)


@app.command("detectors")
def list_detectors(
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Include known limitations.")
    ] = False,
) -> None:
    """List detection engines and what each one is known to miss."""
    from supplyguard.detectors.base import all_detectors

    for engine in all_detectors():
        info = engine.describe()
        console.print(
            Panel(
                info["description"]
                + (
                    ""
                    if info["requires_network"]
                    else "\n\n[dim]Runs without network access.[/dim]"
                ),
                title=f"[bold]{info['name']}[/bold]  [dim]({info['category']})[/dim]",
                border_style="blue",
            )
        )
        if verbose:
            for label, items, style in (
                ("False positives", info["known_false_positives"], "yellow"),
                ("False negatives", info["known_false_negatives"], "red"),
            ):
                if items:
                    console.print(f"  [{style}]{label}:[/{style}]")
                    for item in items:
                        console.print(f"    • {item}")
            console.print()


@app.command("ecosystems")
def list_ecosystems() -> None:
    """List supported package ecosystems."""
    from supplyguard.detectors.reference_sets import available_reference_sets
    from supplyguard.ecosystems import all_adapters

    reference_sets = available_reference_sets()
    table = Table(title="Supported ecosystems", header_style="bold")
    table.add_column("Name")
    table.add_column("Description")
    table.add_column("Manifests")
    table.add_column("Downloads")
    table.add_column("Reference set", justify="right")
    for adapter in all_adapters():
        table.add_row(
            adapter.name,
            adapter.display_name,
            ", ".join(adapter.manifest_patterns),
            adapter.download_metric,
            f"{reference_sets.get(adapter.name, 0):,}",
        )
    console.print(table)


@app.command()
def serve(
    host: Annotated[str, typer.Option(help="Bind address.")] = "0.0.0.0",
    port: Annotated[int, typer.Option(help="Port.")] = 8000,
    reload: Annotated[bool, typer.Option(help="Auto-reload on code changes.")] = False,
) -> None:
    """Run the SupplyGuard API server."""
    import uvicorn

    uvicorn.run("supplyguard.api.app:app", host=host, port=port, reload=reload)


# --------------------------------------------------------------------------
# execution
# --------------------------------------------------------------------------

async def _run_scan(
    files: dict[str, str],
    repo: str | None,
    ecosystems: list[str] | None,
    detectors: list[str] | None,
    offline: bool,
    token: str | None,
    redis_url: str | None,
) -> ScanResult:
    from supplyguard.clients.cache import build_cache

    cache = await build_cache(redis_url)
    scanner = Scanner(cache=cache, github_token=token)
    try:
        with console.status("[bold blue]Scanning...", spinner="dots"):
            return await scanner.scan(
                ScanRequest(
                    files=files,
                    repository_url=repo,
                    ecosystems=ecosystems or None,
                    detectors=detectors or None,
                    offline=offline,
                    project_name=repo,
                )
            )
    finally:
        await scanner.aclose()
        await cache.close()


async def _scan_via_api(api_url: str, files: dict[str, str], repo: str | None) -> dict:
    """Submit to a running API and poll until the scan completes."""
    import httpx

    base = api_url.rstrip("/")
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            f"{base}/api/v1/scans",
            json={"files": files, "repository_url": repo},
        )
        response.raise_for_status()
        scan_id = response.json()["scan_id"]
        console.print(f"[dim]Submitted scan {scan_id}; waiting for completion...[/dim]")

        for _ in range(300):
            await asyncio.sleep(1.0)
            poll = await client.get(f"{base}/api/v1/scans/{scan_id}")
            poll.raise_for_status()
            payload = poll.json()
            if payload.get("status") in ("completed", "failed"):
                return payload
        raise TimeoutError(f"Scan {scan_id} did not complete within 5 minutes.")


def _collect_files(paths: list[Path]) -> dict[str, str]:
    """Read manifests from files and directories."""
    from supplyguard.ecosystems import adapter_for_manifest, all_adapters

    config_names = {
        pattern for adapter in all_adapters() for pattern in adapter.registry_config_patterns
    }
    files: dict[str, str] = {}

    def add(path: Path, key: str) -> None:
        try:
            files[key] = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            error_console.print(f"[yellow]Could not read {path}: {exc}[/yellow]")

    for path in paths:
        if path.is_file():
            add(path, path.name)
        elif path.is_dir():
            for child in sorted(path.rglob("*")):
                if not child.is_file() or "node_modules" in child.parts:
                    continue
                if adapter_for_manifest(child.name) or child.name in config_names:
                    add(child, str(child.relative_to(path)))
        else:
            error_console.print(f"[yellow]No such file or directory: {path}[/yellow]")
    return files


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------

def _parse_severity(value: str) -> Severity:
    parsed = Severity.from_label(value)
    if parsed is None:
        raise typer.BadParameter(
            f"Unknown severity {value!r}. Choose from: "
            + ", ".join(s.value for s in SEVERITY_ORDER)
        )
    return parsed


def _render(result: ScanResult, minimum: Severity, show_tree: bool) -> None:
    if result.errors:
        for error in result.errors:
            error_console.print(f"[red]error:[/red] {error}")

    header = Table.grid(padding=(0, 2))
    header.add_column(style="dim")
    header.add_column()
    header.add_row("Project", result.project_name or "(uploaded files)")
    header.add_row("Packages", f"{result.package_count:,}")
    header.add_row("Manifests", ", ".join(e.manifest_filename for e in result.ecosystems) or "-")
    header.add_row("Detectors", ", ".join(result.detectors_run))
    header.add_row("Duration", f"{result.duration_seconds:.1f}s")
    console.print(Panel(header, title="[bold]SupplyGuard scan[/bold]", border_style="blue"))

    if result.risk:
        risk = result.risk
        colour = {"A": "green", "B": "green", "C": "yellow", "D": "red", "F": "bold red"}[risk.grade]
        counts = "  ".join(
            f"[{SEVERITY_STYLES[s.value]}]{risk.by_severity.get(s.value, 0)} {s.value}[/]"
            for s in SEVERITY_ORDER
            if risk.by_severity.get(s.value)
        )
        console.print(
            Panel(
                f"[{colour}]Risk score {risk.score}/100  (grade {risk.grade})[/{colour}]\n"
                f"{risk.total_findings} finding(s)   {counts}"
                + (f"\n\n[yellow]{risk.floor_reason}[/yellow]" if risk.floor_reason else ""),
                border_style=colour,
            )
        )

    shown = [
        f for f in result.findings
        if SEVERITY_ORDER.index(f.severity) <= SEVERITY_ORDER.index(minimum)
    ]
    if not shown:
        console.print("[green]No findings at or above the requested severity.[/green]")
    else:
        _render_findings(shown)

    _render_upgrades(shown)

    if show_tree:
        _render_tree(result)

    if result.notes:
        console.print("\n[dim]Notes[/dim]")
        for note in result.notes[:15]:
            console.print(f"  [dim]• {note}[/dim]")


def _render_upgrades(findings: list) -> None:
    """Aggregate fixes per package into an actionable upgrade plan.

    Twelve separate jackson-databind CVEs are one action, not twelve. This
    resolves the single highest fix version per package so the reader sees the
    upgrade that clears the most findings.
    """
    from supplyguard.ecosystems import get_adapter

    plans: dict[tuple[str, str, str], list] = {}
    for finding in findings:
        if not (finding.fixed_version and finding.package_name and finding.ecosystem):
            continue
        key = (finding.ecosystem, finding.package_name, finding.package_version or "")
        plans.setdefault(key, []).append(finding)
    if not plans:
        return

    table = Table(title="Recommended upgrades", header_style="bold", title_justify="left")
    table.add_column("Package", overflow="fold")
    table.add_column("Current", width=14)
    table.add_column("Upgrade to", width=14)
    table.add_column("Resolves", justify="right", width=9)

    rows = []
    for (ecosystem, name, current), group in plans.items():
        try:
            adapter = get_adapter(ecosystem)
            target = max(
                (f.fixed_version for f in group), key=adapter.parse_version
            )
        except Exception:
            target = sorted(f.fixed_version for f in group)[-1]
        worst = min(group, key=lambda f: SEVERITY_ORDER.index(f.severity))
        rows.append((name, current, target, len(group), SEVERITY_ORDER.index(worst.severity)))

    for name, current, target, count, _ in sorted(rows, key=lambda r: (r[4], -r[3])):
        table.add_row(name, current or "-", target, str(count))
    console.print()
    console.print(table)


#: Per-severity cap, so a project with 200 advisories stays readable.
_MAX_PER_SEVERITY = 12


def _render_findings(findings: list) -> None:
    """Group findings by severity as a wrapped list.

    A five-column table cannot hold a Maven coordinate, a CVE id and a
    description at terminal width without one of them collapsing, so each
    finding gets its own two lines instead.
    """
    for severity in SEVERITY_ORDER:
        group = [f for f in findings if f.severity is severity]
        if not group:
            continue
        style = SEVERITY_STYLES[severity.value]
        console.print(f"\n[{style}] {severity.value.upper()} [/] [bold]({len(group)})[/bold]")
        for finding in group[:_MAX_PER_SEVERITY]:
            label = CATEGORY_LABELS.get(finding.category.value, finding.category.value)
            package = finding.package_name or ""
            if finding.package_version:
                package = f"{package}@{finding.package_version}"
            location = "" if finding.is_direct else f" [dim](depth {finding.depth})[/dim]"
            identifier = f"[bold]{finding.identifier}[/bold]  " if finding.identifier else ""
            fix = f"  [green]-> {finding.fixed_version}[/green]" if finding.fixed_version else ""

            console.print(f"  [dim]{label:<14}[/dim]{identifier}{package}{location}{fix}")
            detail = (
                finding.description
                if finding.category is FindingCategory.VULNERABILITY
                else finding.title
            )
            console.print(f"      [dim]{_truncate(detail, 150)}[/dim]")
        if len(group) > _MAX_PER_SEVERITY:
            console.print(
                f"  [dim]... and {len(group) - _MAX_PER_SEVERITY} more "
                f"{severity.value} finding(s). Use --json for the full list.[/dim]"
            )


def _finding_text(finding) -> str:
    """One-line description, leading with the identifier for advisories."""
    if finding.category is FindingCategory.VULNERABILITY and finding.identifier:
        return f"[bold]{finding.identifier}[/bold] {_truncate(finding.description, 100)}"
    return _truncate(finding.title, 120)


def _truncate(text: str, limit: int) -> str:
    collapsed = " ".join((text or "").split())
    return collapsed if len(collapsed) <= limit else collapsed[: limit - 1] + "\u2026"


def _render_tree(result: ScanResult) -> None:
    """Dependency tree with findings overlaid, capped for terminal sanity."""
    findings_by_package: dict[str, list] = {}
    for finding in result.findings:
        if finding.package_name:
            findings_by_package.setdefault(finding.package_name, []).append(finding)

    for eco in result.ecosystems:
        tree = Tree(f"[bold]{eco.manifest_filename}[/bold] [dim]({eco.ecosystem})[/dim]")
        children: dict[str, list[str]] = {}
        for parent, child in eco.graph.edges:
            children.setdefault(parent, []).append(child)

        def add(node_key: str, branch: Tree, depth: int, seen: set[str]) -> None:
            if depth > 3 or node_key in seen:
                return
            seen = seen | {node_key}
            name = node_key.rsplit("@", 1)[0]
            hits = findings_by_package.get(name, [])
            if hits:
                worst = min(hits, key=lambda f: SEVERITY_ORDER.index(f.severity))
                label = (
                    f"[{SEVERITY_STYLES[worst.severity.value]}]{node_key}[/] "
                    f"[dim]({len(hits)} finding(s))[/dim]"
                )
            else:
                label = f"[dim]{node_key}[/dim]"
            sub = branch.add(label)
            for child in sorted(children.get(node_key, []))[:8]:
                add(child, sub, depth + 1, seen)

        for package in sorted(eco.graph.direct, key=lambda p: p.name)[:20]:
            add(package.key, tree, 0, set())
        console.print(tree)


def _render_api_result(payload: dict, output_json: bool) -> None:
    if output_json:
        console.print_json(jsonlib.dumps(payload))
        return
    risk = payload.get("risk") or {}
    console.print(
        Panel(
            f"Status: {payload.get('status')}\n"
            f"Risk score: {risk.get('score')}/100 (grade {risk.get('grade')})\n"
            f"Findings: {payload.get('finding_count', len(payload.get('findings', [])))}",
            title="[bold]SupplyGuard (via API)[/bold]",
            border_style="blue",
        )
    )
    for finding in payload.get("findings", [])[:25]:
        severity = finding.get("severity", "info")
        console.print(
            f"  [{SEVERITY_STYLES.get(severity, '')}]{severity.upper():8s}[/] "
            f"{finding.get('title')}"
        )


def _result_to_dict(result: ScanResult) -> dict:
    payload = result.summary()
    payload["findings"] = [
        {
            "category": f.category.value,
            "severity": f.severity.value,
            "title": f.title,
            "description": f.description,
            "package_name": f.package_name,
            "package_version": f.package_version,
            "ecosystem": f.ecosystem,
            "identifier": f.identifier,
            "cvss_score": f.cvss_score,
            "affected_range": f.affected_range,
            "fixed_version": f.fixed_version,
            "remediation": f.remediation,
            "references": f.references,
            "confidence": f.confidence,
            "depth": f.depth,
            "is_direct": f.is_direct,
            "detector": f.detector,
            "evidence": [
                {"label": e.label, "detail": e.detail, "weight": e.weight} for e in f.evidence
            ],
            "metadata": f.metadata,
        }
        for f in result.findings
    ]
    return payload


def main() -> None:  # pragma: no cover
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
