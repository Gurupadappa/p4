import { STAGES, type Finding, type PipelineRun } from "../types";

const LABELS: Record<(typeof STAGES)[number], string> = {
  prepare: "Prepare",
  scan: "Scan",
  validate: "Validate",
  prove: "Prove",
};

interface StepperProps {
  run: PipelineRun | null;
  findings: Finding[];
}

function stageMeta(stage: (typeof STAGES)[number], findings: Finding[], activeStage?: string): string {
  if (!findings.length) return stage === activeStage ? "in progress…" : "";
  const confirmed = findings.filter((f) => f.verdict === "confirmed").length;
  const falsePositives = findings.filter((f) => f.verdict === "false_positive").length;
  switch (stage) {
    case "scan":
      return `${findings.length} candidates`;
    case "validate":
      return confirmed || falsePositives ? `${confirmed} confirmed · ${falsePositives} cleared` : "";
    case "prove":
      return confirmed ? `${confirmed} PoCs generated` : "";
    default:
      return "";
  }
}

export function Stepper({ run, findings }: StepperProps) {
  const stage = run?.stage ?? null;
  const idx = stage ? STAGES.indexOf(stage as (typeof STAGES)[number]) : -1;
  const fillPct = stage === "done" ? 100 : idx >= 0 ? (idx / (STAGES.length - 1)) * 100 : 0;

  let statusText = "No run yet — select repos and click Run scan";
  let statusColor = "var(--ink-secondary)";
  if (run?.error) {
    statusText = `Run failed: ${run.error}`;
    statusColor = "var(--status-critical)";
  } else if (run?.stage === "done") {
    statusText = "Run complete";
    statusColor = "var(--status-good-text)";
  } else if (run) {
    statusText = `Running ${LABELS[run.stage as (typeof STAGES)[number]] ?? run.stage}…`;
  }

  return (
    <section className="surface rounded-lg px-6 py-6">
      <div className="mb-5 flex items-center justify-between">
        <span className="font-display text-sm font-semibold">Pipeline</span>
        <span className="font-mono text-[0.76rem]" style={{ color: statusColor }}>
          {run && !run.error && run.stage !== "done" && (
            <span
              className="mr-1.5 inline-block h-2 w-2 animate-pulse rounded-full align-middle"
              style={{ background: "var(--gold)" }}
            />
          )}
          {statusText}
        </span>
      </div>

      <div className="relative">
        <div className="absolute top-4 right-4 left-4 h-0.5" style={{ background: "var(--gridline)" }}>
          <div
            className="h-full transition-all duration-500"
            style={{ width: `${fillPct}%`, background: "var(--gold)" }}
          />
        </div>
        <div className="relative grid grid-cols-4 gap-2">
          {STAGES.map((s, i) => {
            const done = stage === "done" || i < idx;
            const active = i === idx && stage !== "done";
            return (
              <div key={s} className="flex flex-col items-center gap-2 text-center">
                <div
                  className="font-mono flex h-8 w-8 items-center justify-center rounded-full border-2 text-[0.78rem] font-semibold"
                  style={{
                    background: done || active ? "var(--gold)" : "var(--surface)",
                    borderColor: done || active ? "var(--gold)" : "var(--gridline)",
                    color: done || active ? "var(--gold-ink)" : "var(--ink-muted)",
                  }}
                >
                  {i + 1}
                </div>
                <div className="text-[0.8rem] font-medium">{LABELS[s]}</div>
                <div className="ink-muted font-mono h-3.5 text-[0.76rem]">
                  {run ? stageMeta(s, findings, run.error ? undefined : run.stage) : ""}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
