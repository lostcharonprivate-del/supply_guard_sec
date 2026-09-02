import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api/client";
import type { CiEvent, Project, Scan, TrendPoint } from "../api/types";
import { CiTimeline } from "../components/CiTimeline";
import { TrendChart } from "../components/TrendChart";
import { Empty, ErrorBanner, RiskDial, Spinner, formatDate } from "../components/common";

type Tab = "scans" | "ci";

export function ProjectDetail() {
  const { projectId = "" } = useParams();
  const [project, setProject] = useState<Project | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [trend, setTrend] = useState<TrendPoint[]>([]);
  const [events, setEvents] = useState<CiEvent[]>([]);
  const [tab, setTab] = useState<Tab>("scans");
  const [error, setError] = useState<unknown>(null);
  const [ciBusy, setCiBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const [projectData, scanData, trendData, eventData] = await Promise.all([
        api.getProject(projectId),
        api.listScans(projectId),
        api.trend(projectId),
        api.ciEvents(projectId).catch(() => []),
      ]);
      setProject(projectData);
      setScans(scanData);
      setTrend(trendData);
      setEvents(eventData);
    } catch (err) {
      setError(err);
    }
  }, [projectId]);

  useEffect(() => {
    load();
  }, [load]);

  async function runCiScan() {
    setCiBusy(true);
    setError(null);
    try {
      setEvents(await api.runCiScan(projectId, project?.repository_url ?? null));
      setTab("ci");
    } catch (err) {
      setError(err);
    } finally {
      setCiBusy(false);
    }
  }

  if (!project) return error ? <ErrorBanner error={error} /> : <Spinner />;

  return (
    <>
      <div className="page-head">
        <div>
          <h1>{project.name}</h1>
          <p>
            {project.repository_url ? (
              <a href={project.repository_url} target="_blank" rel="noreferrer noopener">
                {project.repository_url}
              </a>
            ) : (
              "Scanned from uploaded manifests"
            )}
          </p>
        </div>
        <div className="spacer" />
        <button onClick={runCiScan} disabled={ciBusy || !project.repository_url}
                title={project.repository_url ? "" : "Add a repository URL to enable CI analysis"}>
          {ciBusy ? <Spinner label="Analysing…" /> : "Analyse CI/CD"}
        </button>
      </div>

      <ErrorBanner error={error} />

      <div className="grid cols-2" style={{ marginBottom: 22 }}>
        <div className="card">
          <h2>Current risk</h2>
          {project.latest_risk_score === null ? (
            <Empty>No completed scans yet.</Empty>
          ) : (
            <div className="risk">
              <RiskDial score={project.latest_risk_score} grade={project.latest_risk_grade ?? "A"} />
              <div className="risk-meta">
                <div>{project.scan_count} scan(s) recorded</div>
                <p style={{ color: "var(--text-dim)", marginBottom: 0 }}>
                  Lower is better. The grade bands are A under 10, B under 25, C under 45,
                  D under 70, F above.
                </p>
              </div>
            </div>
          )}
        </div>

        <div className="card">
          <h2>Risk over time</h2>
          <TrendChart points={trend} />
        </div>
      </div>

      <div className="tabs">
        <button className={tab === "scans" ? "active" : ""} onClick={() => setTab("scans")}>
          Scans ({scans.length})
        </button>
        <button className={tab === "ci" ? "active" : ""} onClick={() => setTab("ci")}>
          CI/CD timeline ({events.length})
        </button>
      </div>

      {tab === "scans" ? (
        scans.length === 0 ? (
          <Empty>No scans yet.</Empty>
        ) : (
          <div className="card">
            <table>
              <thead>
                <tr>
                  <th>Scan</th>
                  <th>Status</th>
                  <th>Packages</th>
                  <th>Findings</th>
                  <th>Risk</th>
                  <th>When</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => (
                  <tr key={scan.id}>
                    <td>
                      <Link to={`/scans/${scan.id}`} className="mono">
                        {scan.id.slice(0, 12)}
                      </Link>
                    </td>
                    <td>{scan.status}</td>
                    <td>{scan.package_count}</td>
                    <td>{scan.finding_count}</td>
                    <td>
                      {scan.risk_score === null ? (
                        "—"
                      ) : (
                        <span className={`grade-${scan.risk_grade}`}>
                          {Math.round(scan.risk_score)} ({scan.risk_grade})
                        </span>
                      )}
                    </td>
                    <td style={{ color: "var(--text-dim)" }}>{formatDate(scan.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      ) : (
        <CiTimeline events={events} />
      )}
    </>
  );
}
