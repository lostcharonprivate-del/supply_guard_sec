/** Types mirroring the SupplyGuard API schemas. */

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type FindingCategory =
  | "vulnerability"
  | "malicious"
  | "typosquat"
  | "dependency_confusion"
  | "ci_anomaly"
  | "stale";

export interface Evidence {
  label: string;
  detail: string;
  weight: number;
}

export interface Finding {
  id: number;
  category: FindingCategory;
  severity: Severity;
  title: string;
  description: string;
  detector: string;
  ecosystem: string | null;
  package_name: string | null;
  package_version: string | null;
  identifier: string | null;
  cvss_score: number | null;
  affected_range: string | null;
  fixed_version: string | null;
  remediation: string | null;
  confidence: number;
  depth: number;
  is_direct: boolean;
  risk_contribution: number;
  references: string[];
  evidence: Evidence[];
  details: Record<string, unknown>;
}

export interface RiskSummary {
  score: number;
  grade: string;
  exposure: number;
  total_findings: number;
  floor_reason: string | null;
  by_severity: Record<string, number>;
  by_category: Record<string, number>;
  category_exposure: Record<string, number>;
  top_contributors: {
    package: string | null;
    category: string;
    severity: string;
    risk: number;
    explanation: string;
  }[];
}

export interface ScanSummary {
  scan_id: string;
  status: string;
  project_name: string | null;
  repository_url: string | null;
  duration_seconds: number;
  package_count: number;
  finding_count: number;
  ecosystems: { ecosystem: string; manifest: string; packages: number; direct: number }[];
  risk: RiskSummary | null;
  detectors_run: string[];
  notes: string[];
  errors: string[];
}

export interface Scan {
  id: string;
  project_id: string;
  status: "queued" | "running" | "completed" | "failed";
  risk_score: number | null;
  risk_grade: string | null;
  package_count: number;
  finding_count: number;
  duration_seconds: number | null;
  started_at: string | null;
  finished_at: string | null;
  error: string | null;
  summary: Partial<ScanSummary>;
  created_at: string;
  findings?: Finding[];
}

export interface Project {
  id: string;
  name: string;
  description: string | null;
  repository_url: string | null;
  settings: Record<string, unknown>;
  created_at: string;
  updated_at: string;
  latest_risk_score: number | null;
  latest_risk_grade: string | null;
  scan_count: number;
}

export interface TreeNode {
  key: string;
  name: string;
  version: string;
  ecosystem: string;
  depth: number;
  is_direct: boolean;
  is_dev: boolean;
  severity: Severity | null;
  finding_count: number;
  children: TreeNode[];
}

export interface TrendPoint {
  scan_id: string;
  created_at: string;
  risk_score: number | null;
  risk_grade: string | null;
  finding_count: number;
}

export interface CiEvent {
  id: number;
  external_id: string;
  provider: string;
  event_type: string;
  severity: Severity;
  title: string;
  description: string;
  remediation: string | null;
  repository: string | null;
  workflow_name: string | null;
  workflow_path: string | null;
  commit_sha: string | null;
  actor: string | null;
  html_url: string | null;
  occurred_at: string | null;
  evidence: Evidence[];
  details: Record<string, unknown>;
  created_at: string;
}

export interface DetectorInfo {
  name: string;
  category: string;
  description: string;
  requires_network: boolean;
  known_false_positives: string[];
  known_false_negatives: string[];
}

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export const CATEGORY_LABELS: Record<FindingCategory, string> = {
  vulnerability: "Vulnerability",
  malicious: "Malicious package",
  typosquat: "Typosquat",
  dependency_confusion: "Dependency confusion",
  ci_anomaly: "CI anomaly",
  stale: "Outdated",
};
