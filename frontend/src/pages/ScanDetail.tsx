import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api/client";
import type { Finding, Scan, TreeNode } from "../api/types";
import { DependencyTree } from "../components/DependencyTree";
import { FindingsList } from "../components/FindingsList";
import { Empty, ErrorBanner, RiskDial, SeverityCounts, Spinner, formatDate } from "../components/common";

type Tab = "findings" | "tree" | "details";

export function ScanDetail() {
  const { scanId = "" } = useParams();
  const [scan, setScan] = useState<(Scan & { findings: Finding[] }) | null>(null);
  const [tree, setTree] = useState<TreeNode[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [tab, setTab] = useState<Tab>("findings");
  const polling = useRef<number | null>(null);

  const load = useCallback(async () => {
    try {
      const result = await api.getScan(scanId);
      setScan(result);
      return result.status;
    } catch (err) {
      setError(err);
      return "failed";
    }
  }, [scanId]);

  useEffect(() => {
    let cancelled = false;
    // A scan runs in the background, so the page polls until it settles rather
    // than blocking on a long request.
    async function tick() {
      const status = await load();
      if (cancelled) return;
      if (status === "queued" || status === "running") {
        polling.current = window.setTimeout(tick, 1500);
      }
    }
    tick();
    return () => {
      cancelled = true;
      if (polling.current) window.clearTimeout(polling.current);
    };
  }, [load]);

  useEffect(() => {
    if (scan?.status === "completed" && tree === null) {
      api.tree(scanId).then(setTree).catch(() => setTree([]));
    }
  }, [scan?.status, scanId, tree]);

  if (error) return <ErrorBanner error={error} />;
  if (!scan) return <Spinner label="Loading scan…" />;

  const summary = scan.summary ?? {};
  const risk = summary.risk ?? null;

  return (
    <>
      <div className="page-head">
        <div>
          <h1>{summary.project_name ?? "Scan"}</h1>
          <p>
            <Link to={`/projects/${scan.project_id}`}>Back to project</Link> · scan{" "}
            <span className="mono">{scan.id.slice(0, 12)}</span> · {formatDate(scan.created_at)}
          </p>
        </div>
      </div>

      {(scan.status === "queued" || scan.status === "running") && (
        <div className="notice" style={{ marginBottom: 18 }}>
          <Spinner label={`Scan is ${scan.status}. Results appear here automatically.`} />
        </div>
      )}
      {scan.status === "failed" && (
        <div className="error-banner">Scan failed: {scan.error ?? "unknown error"}</div>
      )}

      {scan.status === "completed" && (
        <>
          <div className="grid cols-2" style={{ marginBottom: 20 }}>
            <div className="card">
              <h2>Risk</h2>
              <div className="risk">
                <RiskDial score={scan.risk_score ?? 0} grade={scan.risk_grade ?? "A"} />
                <div className="risk-meta">
                  <div>
                    <strong>{scan.finding_count}</strong> findings across{" "}
                    <strong>{scan.package_count}</strong> packages
                  </div>
                  <SeverityCounts counts={risk?.by_severity ?? {}} />
                  {risk?.floor_reason && (
                    <p style={{ color: "var(--critical)", fontSize: 12.5, marginBottom: 0 }}>
                      {risk.floor_reason}
                    </p>
                  )}
                </div>
              </div>
            </div>

            <div className="card">
              <h2>Scope</h2>
              <table>
                <tbody>
                  {(summary.ecosystems ?? []).map((eco) => (
                    <tr key={eco.manifest}>
                      <td className="mono">{eco.manifest}</td>
                      <td style={{ color: "var(--text-dim)" }}>{eco.ecosystem}</td>
                      <td style={{ textAlign: "right" }}>
                        {eco.packages} packages, {eco.direct} direct
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p style={{ color: "var(--text-faint)", fontSize: 12, marginBottom: 0, marginTop: 10 }}>
                Detectors: {(summary.detectors_run ?? []).join(", ")} · completed in{" "}
                {scan.duration_seconds?.toFixed(1)}s
              </p>
            </div>
          </div>

          <div className="tabs">
            {(["findings", "tree", "details"] as Tab[]).map((option) => (
              <button key={option} className={tab === option ? "active" : ""} onClick={() => setTab(option)}>
                {option === "findings"
                  ? `Findings (${scan.findings.length})`
                  : option === "tree"
                    ? "Dependency tree"
                    : "Scan details"}
              </button>
            ))}
          </div>

          {tab === "findings" &&
            (scan.findings.length ? (
              <FindingsList findings={scan.findings} />
            ) : (
              <Empty>No findings. Every dependency in this scan came back clean.</Empty>
            ))}

          {tab === "tree" && (tree === null ? <Spinner /> : <DependencyTree nodes={tree} />)}

          {tab === "details" && (
            <div className="card">
              <h2>Top risk contributors</h2>
              <table>
                <thead>
                  <tr>
                    <th>Package</th>
                    <th>Category</th>
                    <th>Risk</th>
                    <th>Calculation</th>
                  </tr>
                </thead>
                <tbody>
                  {(risk?.top_contributors ?? []).map((row, index) => (
                    <tr key={index}>
                      <td className="mono">{row.package ?? "—"}</td>
                      <td>{row.category}</td>
                      <td>{row.risk.toFixed(2)}</td>
                      <td className="mono" style={{ color: "var(--text-dim)", fontSize: 11.5 }}>
                        {row.explanation}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>

              {(summary.notes ?? []).length > 0 && (
                <>
                  <h2 style={{ marginTop: 22 }}>Notes and caveats</h2>
                  <ul style={{ color: "var(--text-dim)", margin: 0, paddingLeft: 18 }}>
                    {(summary.notes ?? []).map((note, index) => (
                      <li key={index}>{note}</li>
                    ))}
                  </ul>
                </>
              )}
            </div>
          )}
        </>
      )}
    </>
  );
}
