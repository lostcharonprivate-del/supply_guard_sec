import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api/client";
import { ErrorBanner, Spinner } from "../components/common";

/** Submit a scan from uploaded manifests or a repository URL.
 *
 * Files are read in the browser and posted as text rather than multipart: the
 * API accepts either, and this keeps the same code path as the CLI.
 */
export function NewScanForm({ onComplete }: { onComplete?: () => void }) {
  const navigate = useNavigate();
  const [mode, setMode] = useState<"files" | "repo">("files");
  const [files, setFiles] = useState<Record<string, string>>({});
  const [repositoryUrl, setRepositoryUrl] = useState("");
  const [projectName, setProjectName] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [status, setStatus] = useState<string | null>(null);

  async function onFilesChosen(event: React.ChangeEvent<HTMLInputElement>) {
    const chosen = Array.from(event.target.files ?? []);
    const contents: Record<string, string> = {};
    for (const file of chosen) contents[file.name] = await file.text();
    setFiles(contents);
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    setStatus("Submitting…");
    try {
      const { scan_id } = await api.createScan({
        files: mode === "files" ? files : {},
        repository_url: mode === "repo" ? repositoryUrl : null,
        project_name: projectName || (mode === "repo" ? repositoryUrl : null),
      });
      setStatus("Scanning…");
      onComplete?.();
      navigate(`/scans/${scan_id}`);
    } catch (err) {
      setError(err);
      setStatus(null);
    }
  }

  const ready = mode === "files" ? Object.keys(files).length > 0 : repositoryUrl.trim().length > 0;

  return (
    <form onSubmit={submit}>
      <ErrorBanner error={error} />

      <div className="tabs">
        <button type="button" className={mode === "files" ? "active" : ""} onClick={() => setMode("files")}>
          Upload manifests
        </button>
        <button type="button" className={mode === "repo" ? "active" : ""} onClick={() => setMode("repo")}>
          GitHub repository
        </button>
      </div>

      {mode === "files" ? (
        <div className="field">
          <label htmlFor="manifests">
            Lockfiles or manifests (package-lock.json, poetry.lock, Gemfile.lock, pom.xml…)
          </label>
          <input id="manifests" type="file" multiple onChange={onFilesChosen} />
          {Object.keys(files).length > 0 && (
            <p style={{ color: "var(--text-dim)", fontSize: 12, marginBottom: 0 }}>
              {Object.keys(files).join(", ")}
            </p>
          )}
        </div>
      ) : (
        <div className="field">
          <label htmlFor="repo">Repository</label>
          <input
            id="repo" placeholder="owner/repo or https://github.com/owner/repo"
            value={repositoryUrl} onChange={(e) => setRepositoryUrl(e.target.value)}
          />
        </div>
      )}

      <div className="field">
        <label htmlFor="project">Project name (optional)</label>
        <input
          id="project" placeholder="Groups scans together for trend tracking"
          value={projectName} onChange={(e) => setProjectName(e.target.value)}
        />
      </div>

      <button className="primary" type="submit" disabled={!ready || status !== null}>
        {status ? <Spinner label={status} /> : "Start scan"}
      </button>
    </form>
  );
}
