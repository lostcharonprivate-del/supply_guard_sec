import type { ReactNode } from "react";
import type { Severity } from "../api/types";
import { SEVERITY_ORDER } from "../api/types";

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`badge sev-${severity}`}>{severity}</span>;
}

export function SeverityCounts({ counts }: { counts: Record<string, number> }) {
  const present = SEVERITY_ORDER.filter((s) => counts[s]);
  if (!present.length) return <span className="chip">No findings</span>;
  return (
    <div className="sev-counts">
      {present.map((severity) => (
        <span key={severity} className={`badge sev-${severity}`}>
          {counts[severity]} {severity}
        </span>
      ))}
    </div>
  );
}

/** Risk score as a dial.
 *
 * The arc is drawn rather than charted: a single number with a grade is what a
 * reader acts on, and a full chart library for one value is not worth the
 * bundle. */
export function RiskDial({ score, grade }: { score: number; grade: string }) {
  const radius = 46;
  const circumference = 2 * Math.PI * radius;
  const filled = (Math.min(100, Math.max(0, score)) / 100) * circumference;
  const colour = { A: "--ok", B: "--ok", C: "--medium", D: "--high", F: "--critical" }[grade] ?? "--info";

  return (
    <figure className="risk-dial" style={{ margin: 0 }}>
      <svg viewBox="0 0 108 108" width="108" height="108" role="img"
           aria-label={`Risk score ${score} out of 100, grade ${grade}`}>
        <circle cx="54" cy="54" r={radius} fill="none" stroke="var(--border)" strokeWidth="7" />
        <circle
          cx="54" cy="54" r={radius} fill="none"
          stroke={`var(${colour})`} strokeWidth="7" strokeLinecap="round"
          strokeDasharray={`${filled} ${circumference - filled}`}
          transform="rotate(-90 54 54)"
        />
      </svg>
      <figcaption>
        <span className={`score grade-${grade}`}>{Math.round(score)}</span>
        <span className="grade">grade {grade}</span>
      </figcaption>
    </figure>
  );
}

export function Spinner({ label }: { label?: string }) {
  return (
    <span>
      <span className="spinner" /> {label ?? "Loading"}
    </span>
  );
}

export function ErrorBanner({ error }: { error: unknown }) {
  if (!error) return null;
  const message = error instanceof Error ? error.message : String(error);
  return <div className="error-banner">{message}</div>;
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

export function formatDate(value: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleString(undefined, {
    year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
  });
}

export function relativeTime(value: string | null): string {
  if (!value) return "";
  const then = new Date(value).getTime();
  if (Number.isNaN(then)) return "";
  const seconds = Math.round((Date.now() - then) / 1000);
  const units: [number, Intl.RelativeTimeFormatUnit][] = [
    [60, "second"], [3600, "minute"], [86400, "hour"], [2592000, "day"], [31536000, "month"],
  ];
  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  if (seconds < 60) return formatter.format(-seconds, "second");
  for (let i = 1; i < units.length; i += 1) {
    if (seconds < units[i][0]) {
      return formatter.format(-Math.round(seconds / units[i - 1][0]), units[i][1]);
    }
  }
  return formatter.format(-Math.round(seconds / 31536000), "year");
}
