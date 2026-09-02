import { useEffect, useMemo, useState } from "react";
import type { Finding, FindingCategory, Severity } from "../api/types";
import { CATEGORY_LABELS, SEVERITY_ORDER } from "../api/types";
import { Empty, SeverityBadge } from "./common";

/** Filterable findings list.
 *
 * Filtering happens client-side because the scan payload already contains every
 * finding: a round trip per filter change would be slower and would lose the
 * expanded state of whatever the reader was in the middle of reading.
 */
/** How many findings to render before the reader asks for more.
 *
 * A scan of a real monorepo produces hundreds of findings, and rendering every
 * one as an expandable panel makes the page heavy enough to stutter while
 * scrolling. The reader works top-down through the worst findings anyway, so
 * the tail is rendered on request. */
const INITIAL_RENDER_LIMIT = 50;

export function FindingsList({ findings }: { findings: Finding[] }) {
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [category, setCategory] = useState<FindingCategory | "all">("all");
  const [directOnly, setDirectOnly] = useState(false);
  const [query, setQuery] = useState("");
  const [limit, setLimit] = useState(INITIAL_RENDER_LIMIT);

  const visible = useMemo(() => {
    const maxRank = severity === "all" ? Infinity : SEVERITY_ORDER.indexOf(severity);
    const needle = query.trim().toLowerCase();
    return findings.filter((finding) => {
      if (SEVERITY_ORDER.indexOf(finding.severity) > maxRank) return false;
      if (category !== "all" && finding.category !== category) return false;
      if (directOnly && !finding.is_direct) return false;
      if (needle) {
        const haystack = `${finding.title} ${finding.package_name ?? ""} ${finding.identifier ?? ""}`;
        if (!haystack.toLowerCase().includes(needle)) return false;
      }
      return true;
    });
  }, [findings, severity, category, directOnly, query]);

  // Any filter change puts the reader back at the top of a new result set, so
  // the previous "show more" expansion should not carry over.
  useEffect(() => setLimit(INITIAL_RENDER_LIMIT), [severity, category, directOnly, query]);

  const categories = useMemo(
    () => Array.from(new Set(findings.map((f) => f.category))),
    [findings],
  );

  return (
    <section>
      <div className="filters">
        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value as Severity | "all")}
          aria-label="Minimum severity"
        >
          <option value="all">All severities</option>
          {SEVERITY_ORDER.map((option) => (
            <option key={option} value={option}>
              {option} and above
            </option>
          ))}
        </select>

        <select
          value={category}
          onChange={(e) => setCategory(e.target.value as FindingCategory | "all")}
          aria-label="Finding category"
        >
          <option value="all">All categories</option>
          {categories.map((option) => (
            <option key={option} value={option}>
              {CATEGORY_LABELS[option] ?? option}
            </option>
          ))}
        </select>

        <input
          style={{ width: 220 }}
          placeholder="Filter by package or CVE…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          aria-label="Search findings"
        />

        <label style={{ display: "flex", alignItems: "center", gap: 6, margin: 0 }}>
          <input
            type="checkbox"
            style={{ width: "auto" }}
            checked={directOnly}
            onChange={(e) => setDirectOnly(e.target.checked)}
          />
          Direct dependencies only
        </label>

        <span style={{ color: "var(--text-faint)", marginLeft: "auto", fontSize: 12 }}>
          {visible.length} of {findings.length}
        </span>
      </div>

      {visible.length === 0 ? (
        <Empty>No findings match these filters.</Empty>
      ) : (
        <>
          {visible.slice(0, limit).map((finding) => (
            <FindingRow key={finding.id} finding={finding} />
          ))}
          {visible.length > limit && (
            <button
              style={{ width: "100%", marginTop: 6 }}
              onClick={() => setLimit((current) => current + INITIAL_RENDER_LIMIT)}
            >
              Show {Math.min(INITIAL_RENDER_LIMIT, visible.length - limit)} more
              {" "}({visible.length - limit} remaining)
            </button>
          )}
        </>
      )}
    </section>
  );
}

function FindingRow({ finding }: { finding: Finding }) {
  const location = finding.is_direct ? "direct dependency" : `transitive, depth ${finding.depth}`;

  return (
    <details className="finding">
      <summary>
        <SeverityBadge severity={finding.severity} />
        <span className="finding-title">
          {finding.title}
          <div className="finding-sub">
            {CATEGORY_LABELS[finding.category] ?? finding.category}
            {finding.package_name ? ` · ${location}` : ""}
            {finding.cvss_score !== null ? ` · CVSS ${finding.cvss_score}` : ""}
            {finding.confidence < 1 ? ` · ${Math.round(finding.confidence * 100)}% confidence` : ""}
          </div>
        </span>
        {finding.fixed_version && (
          <span className="chip" style={{ color: "var(--ok)", borderColor: "rgba(55,211,153,0.35)" }}>
            fix: {finding.fixed_version}
          </span>
        )}
      </summary>

      <div className="finding-body">
        <h4>What this means</h4>
        <p>{finding.description}</p>

        {finding.evidence.length > 0 && (
          <>
            <h4>Evidence</h4>
            <ul className="evidence">
              {finding.evidence.map((item, index) => (
                <li key={index}>
                  <strong>{item.label}:</strong> <span>{item.detail}</span>
                </li>
              ))}
            </ul>
          </>
        )}

        {finding.remediation && (
          <>
            <h4>How to fix it</h4>
            <div className="remediation">{finding.remediation}</div>
          </>
        )}

        <h4>Details</h4>
        <table>
          <tbody>
            {finding.package_name && (
              <tr>
                <td style={{ color: "var(--text-dim)", width: 150 }}>Package</td>
                <td className="mono">
                  {finding.package_name}
                  {finding.package_version ? `@${finding.package_version}` : ""}
                </td>
              </tr>
            )}
            {finding.affected_range && (
              <tr>
                <td style={{ color: "var(--text-dim)" }}>Affected range</td>
                <td className="mono">{finding.affected_range}</td>
              </tr>
            )}
            <tr>
              <td style={{ color: "var(--text-dim)" }}>Detector</td>
              <td className="mono">{finding.detector}</td>
            </tr>
            <tr>
              <td style={{ color: "var(--text-dim)" }}>Risk contribution</td>
              <td className="mono">{finding.risk_contribution.toFixed(2)}</td>
            </tr>
          </tbody>
        </table>

        {finding.references.length > 0 && (
          <>
            <h4>References</h4>
            <ul style={{ margin: 0, paddingLeft: 18 }}>
              {finding.references.slice(0, 6).map((url) => (
                <li key={url}>
                  <a href={url} target="_blank" rel="noreferrer noopener">
                    {url}
                  </a>
                </li>
              ))}
            </ul>
          </>
        )}
      </div>
    </details>
  );
}
