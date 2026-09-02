/** Thin API client.
 *
 * Errors are normalised into `ApiError` so that every caller can render a
 * message without unpacking FastAPI's several validation-error shapes.
 */

import type {
  CiEvent,
  DetectorInfo,
  Finding,
  Project,
  Scan,
  TreeNode,
  TrendPoint,
} from "./types";

const TOKEN_KEY = "supplyguard.token";

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string | null): void {
  if (token) localStorage.setItem(TOKEN_KEY, token);
  else localStorage.removeItem(TOKEN_KEY);
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Content-Type", "application/json");
  const token = getToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);

  const response = await fetch(`/api/v1${path}`, { ...init, headers });
  if (response.status === 204) return undefined as T;

  const text = await response.text();
  const payload = text ? JSON.parse(text) : null;

  if (!response.ok) {
    if (response.status === 401) setToken(null);
    throw new ApiError(extractDetail(payload) ?? response.statusText, response.status);
  }
  return payload as T;
}

/** FastAPI reports validation errors as a list of objects, not a string. */
function extractDetail(payload: unknown): string | null {
  if (!payload || typeof payload !== "object") return null;
  const detail = (payload as { detail?: unknown }).detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail
      .map((item) =>
        typeof item === "object" && item && "msg" in item
          ? String((item as { msg: unknown }).msg)
          : String(item),
      )
      .join("; ");
  }
  return null;
}

export const api = {
  register: (email: string, password: string) =>
    request<{ access_token: string }>("/auth/register", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),

  login: (email: string, password: string) =>
    request<{ access_token: string }>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),

  me: () => request<{ id: string; email: string; display_name: string | null }>("/auth/me"),

  listProjects: () => request<Project[]>("/projects"),

  getProject: (id: string) => request<Project>(`/projects/${id}`),

  createProject: (body: { name: string; repository_url?: string | null }) =>
    request<Project>("/projects", { method: "POST", body: JSON.stringify(body) }),

  deleteProject: (id: string) => request<void>(`/projects/${id}`, { method: "DELETE" }),

  trend: (id: string) => request<TrendPoint[]>(`/projects/${id}/trend`),

  listScans: (projectId: string) => request<Scan[]>(`/projects/${projectId}/scans`),

  createScan: (body: {
    files?: Record<string, string>;
    repository_url?: string | null;
    project_id?: string | null;
    project_name?: string | null;
    detectors?: string[] | null;
  }) =>
    request<{ scan_id: string; project_id: string; poll_url: string }>("/scans", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  getScan: (id: string, params: { severity?: string; category?: string } = {}) => {
    const query = new URLSearchParams();
    if (params.severity) query.set("severity", params.severity);
    if (params.category) query.set("category", params.category);
    const suffix = query.toString() ? `?${query}` : "";
    return request<Scan & { findings: Finding[] }>(`/scans/${id}${suffix}`);
  },

  tree: (id: string) => request<TreeNode[]>(`/scans/${id}/tree`),

  ciEvents: (projectId: string) => request<CiEvent[]>(`/projects/${projectId}/ci/events`),

  runCiScan: (projectId: string, repositoryUrl?: string | null) =>
    request<CiEvent[]>(`/projects/${projectId}/ci/scan`, {
      method: "POST",
      body: JSON.stringify({ repository_url: repositoryUrl ?? null, run_limit: 30 }),
    }),

  detectors: () => request<DetectorInfo[]>("/detectors"),
};
