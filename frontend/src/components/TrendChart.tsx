import type { TrendPoint } from "../api/types";
import { formatDate } from "./common";

/** Risk score over time.
 *
 * Hand-drawn SVG rather than a charting dependency: it is one series with a
 * fixed 0-100 domain, and the whole component is smaller than the import would
 * be. The y-axis is pinned to 0-100 so successive scans stay comparable —
 * autoscaling would make a two-point improvement look like a collapse.
 */
export function TrendChart({ points }: { points: TrendPoint[] }) {
  const usable = points.filter((p) => p.risk_score !== null);
  if (usable.length < 2) {
    return (
      <p style={{ color: "var(--text-faint)", margin: 0 }}>
        A trend appears once this project has at least two completed scans.
      </p>
    );
  }

  const width = 640;
  const height = 150;
  const pad = { top: 12, right: 12, bottom: 20, left: 30 };
  const plotWidth = width - pad.left - pad.right;
  const plotHeight = height - pad.top - pad.bottom;

  const x = (i: number) => pad.left + (i / (usable.length - 1)) * plotWidth;
  const y = (score: number) => pad.top + (1 - score / 100) * plotHeight;

  const line = usable.map((p, i) => `${i === 0 ? "M" : "L"}${x(i)},${y(p.risk_score!)}`).join(" ");
  const area = `${line} L${x(usable.length - 1)},${pad.top + plotHeight} L${pad.left},${pad.top + plotHeight} Z`;

  return (
    <svg className="trend" viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none"
         role="img" aria-label="Risk score over time">
      {[0, 50, 100].map((tick) => (
        <g key={tick}>
          <line className="axis" x1={pad.left} y1={y(tick)} x2={width - pad.right} y2={y(tick)} />
          <text x={pad.left - 6} y={y(tick) + 3} textAnchor="end">{tick}</text>
        </g>
      ))}
      <path className="area" d={area} />
      <path className="line" d={line} />
      {usable.map((point, i) => (
        <circle key={point.scan_id} className="dot" cx={x(i)} cy={y(point.risk_score!)} r={3}>
          <title>
            {`${formatDate(point.created_at)}: score ${point.risk_score} (grade ${point.risk_grade}), ${point.finding_count} findings`}
          </title>
        </circle>
      ))}
    </svg>
  );
}
