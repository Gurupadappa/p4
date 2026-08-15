import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import { formatDateTime } from "../lib/format";
import type { PipelineRun } from "../types";

function statusLabel(run: PipelineRun): { text: string; color: string } {
  if (run.error) return { text: "Failed", color: "var(--status-critical)" };
  if (run.stage === "done") return { text: "Complete", color: "var(--status-good-text)" };
  return { text: "In progress", color: "var(--status-warning)" };
}

export function History() {
  const [runs, setRuns] = useState<PipelineRun[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .listRuns()
      .then(({ runs: r }) => setRuns(r))
      .catch((e: Error) => setError(e.message));
  }, []);

  return (
    <main className="flex-1" style={{ background: "var(--page)" }}>
      <div className="mx-auto max-w-7xl px-6 py-10 sm:px-10 sm:py-14">
        <div className="mb-10">
          <p className="font-mono ink-muted mb-2 text-[0.72rem] tracking-[0.14em] uppercase">
            Past runs
          </p>
          <h1 className="font-display m-0 text-3xl font-semibold tracking-tight sm:text-4xl">
            History
          </h1>
        </div>

        {error && (
          <div className="surface rounded-lg px-5 py-8 text-center text-[0.84rem]" style={{ color: "var(--status-critical)" }}>
            Could not load run history: {error}
          </div>
        )}

        {!error && runs === null && (
          <div className="surface ink-muted rounded-lg px-5 py-8 text-center text-[0.84rem]">
            Loading run history…
          </div>
        )}

        {runs !== null && runs.length === 0 && (
          <div className="surface ink-muted rounded-lg px-5 py-8 text-center text-[0.84rem]">
            No scans have been run yet.
          </div>
        )}

        {runs !== null && runs.length > 0 && (
          <div className="flex flex-col gap-3">
            {runs.map((run) => {
              const status = statusLabel(run);
              const s = run.summary;
              return (
                <Link
                  key={run.id}
                  to={`/history/${run.id}`}
                  className="surface flex flex-wrap items-center gap-4 rounded-lg px-5 py-4 no-underline transition-colors"
                  style={{ color: "inherit" }}
                >
                  <div className="min-w-0 flex-1">
                    <div className="text-[0.86rem] font-medium">{run.repos.join(", ") || "—"}</div>
                    <div className="font-mono ink-muted mt-0.5 text-[0.74rem]">
                      {formatDateTime(run.started_at)}
                    </div>
                  </div>
                  <span className="stamp" style={{ color: status.color }}>
                    <span className="stamp-dot" />
                    {status.text}
                  </span>
                  {s && (
                    <div className="font-mono ink-secondary flex flex-wrap gap-3 text-[0.78rem]">
                      <span>{s.total} findings</span>
                      <span>{s.confirmed} confirmed</span>
                      <span>{s.approved} approved</span>
                      <span>{s.rejected} not a vulnerability</span>
                    </div>
                  )}
                  <span className="ink-muted text-[0.9rem]">→</span>
                </Link>
              );
            })}
          </div>
        )}
      </div>
    </main>
  );
}
