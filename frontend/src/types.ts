export const STAGES = ["prepare", "scan", "validate", "prove"] as const;
export type PipelineStage = (typeof STAGES)[number];
export type Stage = PipelineStage | "done";
export type Verdict = "pending" | "confirmed" | "false_positive";
export type ApprovalStatus = "not_applicable" | "awaiting_approval" | "approved" | "rejected";

export interface Finding {
  id: string;
  run_id: string;
  repo: string;
  file: string;
  line: number;
  rule_id: string;
  vuln_class: string;
  severity: string;
  message: string;
  code_snippet: string;
  ground_truth_tag: string | null;

  verdict: Verdict;
  rationale: string;
  confidence: number;
  dedup_signature: string | null;
  dedup_group_id: string | null;
  is_dedup_primary: boolean;

  poc: string | null;
  poc_explanation: string | null;

  verified: boolean | null;
  verification_detail: string | null;

  first_seen: number;
  approval_status: ApprovalStatus;
  fix_patch: string | null;

  age_seconds: number;
  sla_breached: boolean;
}

export interface RunSummary {
  total: number;
  confirmed: number;
  false_positive: number;
  awaiting_approval: number;
  approved: number;
  rejected: number;
}

export interface PipelineRun {
  id: string;
  repos: string[];
  stage: Stage;
  started_at: number;
  finished_at: number | null;
  error: string | null;
  summary?: RunSummary;
}

export interface MetricSet {
  true_positives: number;
  false_positives: number;
  false_negatives: number;
  precision: number;
  recall: number;
  f1: number;
}

export interface Report {
  total_true_vulns_planted: number;
  answer_key_coverage: string;
  baseline: MetricSet;
  pipeline: MetricSet;
  false_positive_suppression_rate: number | null;
  cross_repo_dedup_groups: number;
}

export interface DefectDojoResult {
  synced: boolean;
  target?: string;
  count?: number;
  would_sync_count?: number;
  artifact_path?: string;
  note?: string;
}
