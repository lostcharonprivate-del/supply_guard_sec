import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import type { Project } from "../api/types";
import { Empty, ErrorBanner, Spinner, formatDate } from "../components/common";
import { NewScanForm } from "./NewScan";

export function Projects() {
  const [projects, setProjects] = useState<Project[] | null>(null);
  const [error, setError] = useState<unknown>(null);

  const load = useCallback(() => {
    api.listProjects().then(setProjects).catch(setError);
  }, []);

  useEffect(load, [load]);

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Projects</h1>
          <p>Every project you have scanned, with its most recent risk score.</p>
        </div>
      </div>

      <ErrorBanner error={error} />

      <div className="grid cols-2" style={{ marginBottom: 24 }}>
        <div className="card">
          <h2>New scan</h2>
          <NewScanForm onComplete={load} />
        </div>

        <div className="card">
          <h2>How scoring works</h2>
          <p style={{ color: "var(--text-dim)", margin: 0 }}>
            A project&rsquo;s score multiplies each finding&rsquo;s severity by how exploitable
            it is (read from the CVSS vector), how deep in the dependency tree it sits, and
            how confident the detector is. Direct dependencies weigh more than deeply
            transitive ones because they are both more reachable and more actionable.
          </p>
          <p style={{ color: "var(--text-dim)", marginBottom: 0 }}>
            A confirmed-malicious package floors the score in the failing band regardless of
            the arithmetic: attacker code in the tree has already run at install time.
          </p>
        </div>
      </div>

      {projects === null ? (
        <Spinner />
      ) : projects.length === 0 ? (
        <Empty>No projects yet. Start a scan above.</Empty>
      ) : (
        <div className="card">
          <table>
            <thead>
              <tr>
                <th>Project</th>
                <th>Repository</th>
                <th>Scans</th>
                <th>Risk</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {projects.map((project) => (
                <tr key={project.id}>
                  <td>
                    <Link to={`/projects/${project.id}`}>{project.name}</Link>
                  </td>
                  <td className="mono" style={{ color: "var(--text-dim)" }}>
                    {project.repository_url ?? "—"}
                  </td>
                  <td>{project.scan_count}</td>
                  <td>
                    {project.latest_risk_score === null ? (
                      <span style={{ color: "var(--text-faint)" }}>—</span>
                    ) : (
                      <span className={`grade-${project.latest_risk_grade}`}>
                        {Math.round(project.latest_risk_score)} ({project.latest_risk_grade})
                      </span>
                    )}
                  </td>
                  <td style={{ color: "var(--text-dim)" }}>{formatDate(project.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
