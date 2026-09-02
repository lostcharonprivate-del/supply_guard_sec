"""OSV.dev client — the primary vulnerability and malicious-package source.

OSV is used for two jobs at once:

* **Vulnerabilities.** OSV performs the affected-range matching server-side,
  which is why SupplyGuard does not implement four ecosystems' worth of version
  range semantics locally.
* **Malicious packages.** The `ossf/malicious-packages` dataset is published
  into OSV under `MAL-` identifiers, so the same query that finds CVEs also
  finds known-malicious releases at no extra cost.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, ClassVar

from supplyguard.clients.http import HttpClient
from supplyguard.core.cvss import score_from_vector
from supplyguard.core.types import PackageRef, Severity
from supplyguard.utils.dates import parse_iso

logger = logging.getLogger(__name__)

API = "https://api.osv.dev/v1"
#: OSV accepts up to 1000 queries per batch; stay well under to keep latency sane.
BATCH_SIZE = 200
#: Advisory documents are effectively immutable, so they cache for a week.
VULN_TTL = 604_800
QUERY_TTL = 21_600  # 6h: new advisories should surface the same day.


@dataclass(slots=True)
class Vulnerability:
    """A normalised OSV advisory, resolved against one specific package version."""

    id: str
    summary: str
    details: str
    aliases: list[str] = field(default_factory=list)
    severity: Severity = Severity.MEDIUM
    cvss_score: float | None = None
    cvss_vector: str | None = None
    exploitability: float = 1.0
    introduced: str | None = None
    fixed_version: str | None = None
    affected_range: str | None = None
    references: list[str] = field(default_factory=list)
    published: datetime | None = None
    withdrawn: datetime | None = None
    cwe_ids: list[str] = field(default_factory=list)

    #: CWEs that mean "this package contains attacker-planted code", as opposed
    #: to an ordinary defect. CWE-506 is Embedded Malicious Code; CWE-912 is
    #: Hidden Functionality.
    MALICIOUS_CWES: ClassVar[frozenset[str]] = frozenset({"CWE-506", "CWE-912"})

    @property
    def is_malicious(self) -> bool:
        """Whether this advisory describes a *malicious package*, not a bug.

        Three sources agree on this, and all three matter:

        * `MAL-` identifiers — the `ossf/malicious-packages` feed republished
          through OSV.
        * CWE-506 / CWE-912 — how the GitHub Advisory Database tags a package
          that shipped attacker-planted code. Both the `event-stream` and
          `ua-parser-js` compromises are GHSA entries carrying CWE-506, so
          without this they would be reported as ordinary vulnerabilities.
        * An explicit statement in the summary, as a last resort.
        """
        if self.id.startswith("MAL-"):
            return True
        if self.MALICIOUS_CWES.intersection(self.cwe_ids):
            return True
        text = f"{self.summary}".lower()
        return any(
            phrase in text
            for phrase in ("malicious code in", "embedded malware", "malicious package")
        )

    @property
    def malicious_source(self) -> str:
        """Where the malicious classification came from, stated accurately."""
        if self.id.startswith("MAL-"):
            return "the OSV malicious-package feed (ossf/malicious-packages)"
        if self.MALICIOUS_CWES.intersection(self.cwe_ids):
            weaknesses = ", ".join(sorted(self.MALICIOUS_CWES.intersection(self.cwe_ids)))
            return f"the GitHub Advisory Database, tagged {weaknesses} (embedded malicious code)"
        return "an advisory that describes this package as malicious"

    @property
    def cve_id(self) -> str | None:
        return next((a for a in self.aliases if a.startswith("CVE-")), None)

    @property
    def primary_id(self) -> str:
        return self.cve_id or self.id


class OSVClient:
    def __init__(self, http: HttpClient) -> None:
        self.http = http

    # -- batch lookup --------------------------------------------------------
    async def query_batch(self, refs: list[PackageRef]) -> dict[str, list[str]]:
        """Map `PackageRef.key` -> advisory IDs affecting that exact version.

        Uses OSV's batch endpoint, which returns IDs only; full documents are
        fetched once each afterwards and cached hard. For a lockfile with 250
        packages sharing 30 advisories this is ~2 batch calls plus 30 lookups
        instead of 250 individual queries.
        """
        results: dict[str, list[str]] = {}
        ecosystem_map = {r.key: r for r in refs}
        queryable = [r for r in ecosystem_map.values() if r.version]

        for start in range(0, len(queryable), BATCH_SIZE):
            chunk = queryable[start : start + BATCH_SIZE]
            body = {
                "queries": [
                    {
                        "package": {"name": r.name, "ecosystem": r.ecosystem},
                        "version": r.version,
                    }
                    for r in chunk
                ]
            }
            try:
                response = await self.http.post_json(
                    f"{API}/querybatch", body, ttl=QUERY_TTL
                )
            except Exception as exc:
                logger.warning("OSV batch query failed for %d packages: %s", len(chunk), exc)
                continue
            for ref, entry in zip(chunk, (response or {}).get("results") or [], strict=False):
                ids = [v["id"] for v in (entry or {}).get("vulns") or [] if v.get("id")]
                if ids:
                    results[ref.key] = ids
        return results

    # -- advisory documents --------------------------------------------------
    async def fetch_vulnerabilities(self, ids: list[str]) -> dict[str, dict]:
        """Fetch full advisory documents for a set of IDs, concurrently."""
        unique = sorted(set(ids))
        docs: dict[str, dict] = {}

        async def one(vuln_id: str) -> None:
            try:
                data = await self.http.get_json(f"{API}/vulns/{vuln_id}", ttl=VULN_TTL)
            except Exception as exc:
                logger.warning("OSV lookup failed for %s: %s", vuln_id, exc)
                return
            if data:
                docs[vuln_id] = data

        await self.http.gather([one(i) for i in unique])
        return docs

    async def query_one(self, ref: PackageRef) -> list[Vulnerability]:
        """Single-package query. Convenient for the CLI and for tests."""
        body: dict[str, Any] = {"package": {"name": ref.name, "ecosystem": ref.ecosystem}}
        if ref.version:
            body["version"] = ref.version
        response = await self.http.post_json(f"{API}/query", body, ttl=QUERY_TTL)
        return [
            parse_vulnerability(doc, ref)
            for doc in (response or {}).get("vulns") or []
        ]

    async def scan(self, refs: list[PackageRef]) -> dict[str, list[Vulnerability]]:
        """Full pipeline: batch query, fetch documents, normalise per package."""
        id_map = await self.query_batch(refs)
        if not id_map:
            return {}
        all_ids = [i for ids in id_map.values() for i in ids]
        docs = await self.fetch_vulnerabilities(all_ids)

        by_ref = {r.key: r for r in refs}
        out: dict[str, list[Vulnerability]] = {}
        for key, ids in id_map.items():
            ref = by_ref.get(key)
            if ref is None:
                continue
            vulns = [
                parse_vulnerability(docs[i], ref) for i in ids if i in docs
            ]
            # An advisory that has been withdrawn is not a finding.
            vulns = [v for v in vulns if v.withdrawn is None]
            if vulns:
                out[key] = vulns
        return out


# --------------------------------------------------------------------------
# normalisation
# --------------------------------------------------------------------------

def parse_vulnerability(doc: dict, ref: PackageRef) -> Vulnerability:
    """Normalise an OSV document against the package version being scanned."""
    severity_entries = doc.get("severity") or []
    vector = next(
        (
            s.get("score")
            for s in severity_entries
            if str(s.get("type", "")).startswith("CVSS") and s.get("score")
        ),
        None,
    )
    score, exploitability = score_from_vector(vector)

    db_specific = doc.get("database_specific") or {}
    label_severity = Severity.from_label(db_specific.get("severity"))

    # Prefer the computed numeric score; fall back to the advisory's own label.
    if score is not None:
        severity = Severity.from_cvss(score)
    elif label_severity is not None:
        severity = label_severity
    else:
        severity = Severity.HIGH if doc.get("id", "").startswith("MAL-") else Severity.MEDIUM

    introduced, fixed, range_text = _resolve_range(doc, ref)

    return Vulnerability(
        id=doc.get("id", "UNKNOWN"),
        summary=(doc.get("summary") or "").strip() or _first_line(doc.get("details")),
        details=(doc.get("details") or "").strip(),
        aliases=list(doc.get("aliases") or []),
        severity=severity,
        cvss_score=score,
        cvss_vector=vector,
        exploitability=exploitability,
        introduced=introduced,
        fixed_version=fixed,
        affected_range=range_text,
        references=[
            r.get("url") for r in (doc.get("references") or []) if r.get("url")
        ][:8],
        published=parse_iso(doc.get("published")),
        withdrawn=parse_iso(doc.get("withdrawn")),
        cwe_ids=list(db_specific.get("cwe_ids") or []),
    )


def _resolve_range(doc: dict, ref: PackageRef) -> tuple[str | None, str | None, str | None]:
    """Extract the introduced/fixed pair that actually applies to `ref.version`.

    Two subtleties make this more than `affected[0]["ranges"][0]`:

    * One advisory can cover many packages across many ecosystems (a Maven
      advisory routinely lists a dozen artifacts), so the entry must be matched
      on both ecosystem and name.
    * A package maintained on several release branches gets one `affected`
      entry per branch. minimist's GHSA-vh95-rmgr-6w4m is fixed in 0.2.1 on the
      0.x branch and 1.2.3 on the 1.x branch; telling a user on 1.2.0 to move
      to 0.2.1 would be advice to downgrade into a different vulnerability.
      The branch whose range contains the scanned version wins.
    """
    from supplyguard.ecosystems.base import adapter_for_osv_ecosystem

    adapter = adapter_for_osv_ecosystem(ref.ecosystem)
    normalised = adapter.normalize_name(ref.name) if adapter else ref.name.lower()

    def version_key(value: str) -> tuple | None:
        if not adapter or not value:
            return None
        try:
            return adapter.parse_version(value)
        except Exception:
            return None

    current = version_key(ref.version) if ref.version else None
    candidates: list[tuple[str | None, str | None, str | None]] = []
    enumerated: list[str] = []

    for affected in doc.get("affected") or []:
        package = affected.get("package") or {}
        eco = (package.get("ecosystem") or "").split(":")[0].strip().lower()
        if eco != ref.ecosystem.split(":")[0].strip().lower():
            continue
        name = package.get("name") or ""
        if (adapter.normalize_name(name) if adapter else name.lower()) != normalised:
            continue

        for range_entry in affected.get("ranges") or []:
            events = range_entry.get("events") or []
            candidates.append(
                (
                    next((e["introduced"] for e in events if "introduced" in e), None),
                    next((e["fixed"] for e in events if "fixed" in e), None),
                    next((e["last_affected"] for e in events if "last_affected" in e), None),
                )
            )
        enumerated.extend(affected.get("versions") or [])

    if not candidates:
        if enumerated:
            return None, None, f"{len(enumerated)} affected version(s) enumerated"
        return None, None, None

    def contains(candidate: tuple) -> bool:
        introduced, fixed, last_affected = candidate
        if current is None:
            return False
        low = version_key(introduced) if introduced and introduced != "0" else None
        if low is not None and current < low:
            return False
        high = version_key(fixed)
        if high is not None:
            return current < high
        last = version_key(last_affected)
        if last is not None:
            return current <= last
        return True

    chosen = next((c for c in candidates if contains(c)), None)
    if chosen is None:
        # No branch contains the version (possible when OSV matched on an
        # enumerated version list). Prefer the newest branch as the best guess.
        chosen = max(
            candidates,
            key=lambda c: version_key(c[0]) or (),
            default=candidates[0],
        )

    introduced, fixed, last_affected = chosen
    if fixed:
        text = f">={introduced or '0'} <{fixed}"
    elif last_affected:
        text = f">={introduced or '0'} <={last_affected}"
    else:
        text = f">={introduced or '0'}"
    return introduced, fixed, text


def _first_line(details: str | None) -> str:
    if not details:
        return "No summary provided by the advisory."
    for line in details.strip().splitlines():
        cleaned = line.strip().lstrip("#").strip()
        if cleaned:
            return cleaned[:300]
    return "No summary provided by the advisory."


async def _selftest() -> None:  # pragma: no cover - manual smoke helper
    async with HttpClient() as http:
        client = OSVClient(http)
        refs = [
            PackageRef("npm", "lodash", "4.17.15"),
            PackageRef("npm", "minimist", "1.2.0"),
            PackageRef("npm", "express", "4.17.1"),
            PackageRef("PyPI", "django", "3.2.0"),
        ]
        found = await client.scan(refs)
        for key, vulns in sorted(found.items()):
            print(f"{key}: {len(vulns)} advisories")
            for v in vulns[:3]:
                print(f"   {v.primary_id:20s} {v.severity:8s} cvss={v.cvss_score} fix={v.fixed_version}")
        print("http:", http.stats.as_dict())


if __name__ == "__main__":  # pragma: no cover
    asyncio.run(_selftest())
