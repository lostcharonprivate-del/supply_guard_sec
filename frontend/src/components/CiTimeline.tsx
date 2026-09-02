import type { CiEvent } from "../api/types";
import { Empty, SeverityBadge, formatDate, relativeTime } from "./common";

/** CI/CD events as a chronological feed.
 *
 * Build-integrity problems are things that happened in sequence — permissions
 * widened here, an action repointed there — and a score would collapse exactly
 * the ordering an incident responder needs.
 */
export function CiTimeline({ events }: { events: CiEvent[] }) {
  if (!events.length) {
    return (
      <Empty>
        No CI events recorded yet. Run an analysis to inspect this repository&rsquo;s
        GitHub Actions workflows and recent runs.
      </Empty>
    );
  }

  return (
    <div className="timeline">
      {events.map((event) => (
        <article key={event.id} className={`timeline-item sev-dot-${event.severity}`}>
          <div style={{ display: "flex", alignItems: "baseline", gap: 10, flexWrap: "wrap" }}>
            <SeverityBadge severity={event.severity} />
            <strong style={{ fontWeight: 540 }}>{event.title}</strong>
            <span className="timeline-time">
              {event.occurred_at ? relativeTime(event.occurred_at) : "from current configuration"}
            </span>
          </div>

          <p style={{ color: "var(--text-dim)", margin: "6px 0 0" }}>{event.description}</p>

          {event.evidence.length > 0 && (
            <ul className="evidence" style={{ marginTop: 8 }}>
              {event.evidence.map((item, index) => (
                <li key={index}>
                  <strong>{item.label}:</strong> <span>{item.detail}</span>
                </li>
              ))}
            </ul>
          )}

          {event.remediation && (
            <div className="remediation" style={{ marginTop: 8 }}>{event.remediation}</div>
          )}

          <div style={{ marginTop: 8, display: "flex", gap: 8, flexWrap: "wrap", fontSize: 12 }}>
            <span className="chip">{event.event_type.replace(/_/g, " ")}</span>
            {event.workflow_path && <span className="chip mono">{event.workflow_path}</span>}
            {event.commit_sha && <span className="chip mono">{event.commit_sha.slice(0, 8)}</span>}
            {event.actor && <span className="chip">by {event.actor}</span>}
            {event.occurred_at && <span className="chip">{formatDate(event.occurred_at)}</span>}
            {event.html_url && (
              <a href={event.html_url} target="_blank" rel="noreferrer noopener">
                View on GitHub
              </a>
            )}
          </div>
        </article>
      ))}
    </div>
  );
}
