import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ComparisonPanel } from "../components/ComparisonPanel";
import { FindingsList } from "../components/FindingsList";
import { Toast } from "../components/Toast";
import { useToast } from "../hooks/useToast";
import { useFindingActions } from "../hooks/useFindingActions";
import { api } from "../lib/api";
import { formatDateTime } from "../lib/format";
import type { Finding, PipelineRun, Report } from "../types";

export function HistoryDetail() {
  const { runId } = useParams<{ runId: string }>();
  const { message, showToast } = useToast();

  const [run, setRun] = useState<PipelineRun | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    if (!runId) return;
    setLoaded(false);
    Promise.all([api.getRun(runId), api.getFindings(runId), api.getReport(runId)])
      .then(([runRes, findingsRes, reportRes]) => {
        setRun(runRes);
        setFindings(findingsRes.findings);
        setReport(reportRes);
        setLoaded(true);
      })
      .catch((e: Error) => {
        setError(e.message);
        setLoaded(true);
      });
  }, [runId]);

  const applyFindingUpdate = useCallback((updated: Finding) => {
    setFindings((current) => current.map((f) => (f.id === updated.id ? updated : f)));
  }, []);
  const { handleApprove, handleReject } = useFindingActions(applyFindingUpdate, showToast);

  return (
    <main className="flex-1" style={{ background: "var(--page)" }}>
      <div className="mx-auto max-w-7xl px-6 py-10 sm:px-10 sm:py-14">
        <div className="mb-10">
          <Link to="/history" className="font-mono ink-muted mb-2 inline-block text-[0.72rem] tracking-[0.14em] uppercase no-underline">
            ← Back to history
          </Link>
          {run && (
            <>
              <h1 className="font-display m-0 text-3xl font-semibold tracking-tight sm:text-4xl">
                {run.repos.join(", ") || "Run"}
              </h1>
              <p className="font-mono ink-secondary mt-2 text-[0.8rem]">
                {formatDateTime(run.started_at)}
                {run.error ? ` · failed: ${run.error}` : run.stage === "done" ? " · complete" : " · in progress"}
              </p>
            </>
          )}
        </div>

        {!loaded && (
          <div className="surface ink-muted rounded-lg px-5 py-8 text-center text-[0.84rem]">
            Loading run…
          </div>
        )}

        {loaded && error && (
          <div className="surface rounded-lg px-5 py-8 text-center text-[0.84rem]" style={{ color: "var(--status-critical)" }}>
            Could not load run: {error}
          </div>
        )}

        {loaded && !error && (
          <div className="flex flex-col gap-8">
            <ComparisonPanel report={report} findings={findings} />
            <FindingsList findings={findings} onApprove={handleApprove} onReject={handleReject} />
          </div>
        )}
      </div>
      <Toast message={message} />
    </main>
  );
}
