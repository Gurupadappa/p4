import type { DefectDojoResult, Finding, PipelineRun, Report } from "../types";

class ApiError extends Error {}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, init);
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new ApiError(`${res.status} ${res.statusText}: ${body.slice(0, 200)}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  listRepos: () => request<{ repos: string[] }>("/api/repos"),

  startScan: (repos: string[]) =>
    request<{ run_id: string }>("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ repos }),
    }),

  listRuns: () => request<{ runs: PipelineRun[] }>("/api/runs"),

  getRun: (runId: string) => request<PipelineRun>(`/api/runs/${runId}`),

  getFindings: (runId: string) =>
    request<{ findings: Finding[] }>(`/api/runs/${runId}/findings`),

  getReport: (runId: string) => request<Report>(`/api/runs/${runId}/report`),

  approveFinding: (findingId: string) =>
    request<Finding>(`/api/findings/${findingId}/approve`, { method: "POST" }),

  rejectFinding: (findingId: string) =>
    request<Finding>(`/api/findings/${findingId}/reject`, { method: "POST" }),

  syncDefectDojo: (runId: string) =>
    request<DefectDojoResult>(`/api/runs/${runId}/defectdojo`, { method: "POST" }),
};

export { ApiError };
