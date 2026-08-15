import { useCallback, useEffect, useState } from "react";
import { Stepper } from "../components/Stepper";
import { ComparisonPanel } from "../components/ComparisonPanel";
import { FindingsList } from "../components/FindingsList";
import { RemediationPanel } from "../components/RemediationPanel";
import { Toast } from "../components/Toast";
import { useToast } from "../hooks/useToast";
import { useScanRun } from "../hooks/useScanRun";
import { useFindingActions } from "../hooks/useFindingActions";
import { api } from "../lib/api";

export function Dashboard() {
  const { message, showToast } = useToast();
  const { run, findings, report, starting, running, startScan, applyFindingUpdate } =
    useScanRun(showToast);
  const { handleApprove, handleReject } = useFindingActions(applyFindingUpdate, showToast);

  const [repos, setRepos] = useState<string[]>([]);
  const [selectedRepos, setSelectedRepos] = useState<Set<string>>(new Set());

  useEffect(() => {
    api
      .listRepos()
      .then(({ repos: names }) => {
        setRepos(names);
        setSelectedRepos(new Set(names));
      })
      .catch((e: Error) => showToast(`Could not load repos: ${e.message}`));
  }, [showToast]);

  const toggleRepo = useCallback((name: string) => {
    setSelectedRepos((current) => {
      const next = new Set(current);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  }, []);

  const handleRunScan = useCallback(() => {
    const selected = Array.from(selectedRepos);
    if (!selected.length) {
      showToast("Select at least one repo");
      return;
    }
    startScan(selected);
  }, [selectedRepos, showToast, startScan]);

  return (
    <main className="flex-1" style={{ background: "var(--page)" }}>
      <div className="mx-auto max-w-7xl px-6 py-10 sm:px-10 sm:py-14">
        <div className="mb-10 flex flex-wrap items-end justify-between gap-6">
          <div>
            <p className="font-mono ink-muted mb-2 text-[0.72rem] tracking-[0.14em] uppercase">
              Triage console
            </p>
            <h1 className="font-display m-0 text-3xl font-semibold tracking-tight sm:text-4xl">
              Dashboard
            </h1>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <div className="flex flex-wrap gap-2" role="group" aria-label="Repositories to scan">
              {repos.map((name) => {
                const checked = selectedRepos.has(name);
                return (
                  <label
                    key={name}
                    className="font-mono flex cursor-pointer items-center gap-1.5 rounded-full border px-3 py-1.5 text-[0.74rem] transition-colors"
                    style={{
                      borderColor: checked ? "var(--gold)" : "var(--border)",
                      background: checked ? "var(--accent-wash)" : "var(--card)",
                      color: checked ? "var(--gold)" : "var(--ink-secondary)",
                    }}
                  >
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={() => toggleRepo(name)}
                      className="sr-only"
                    />
                    {name}
                  </label>
                );
              })}
            </div>
            <button
              type="button"
              onClick={handleRunScan}
              disabled={running || starting}
              className="cursor-pointer rounded-full border-none px-6 py-2.5 text-[0.84rem] font-semibold disabled:cursor-not-allowed disabled:opacity-60"
              style={{ background: "var(--brand)", color: "var(--brand-ink)" }}
            >
              {starting ? "Starting…" : running ? "Running…" : "Run scan"}
            </button>
          </div>
        </div>

        <div className="flex flex-col gap-8">
          <Stepper run={run} findings={findings} />
          <ComparisonPanel report={report} findings={findings} />
          <FindingsList findings={findings} onApprove={handleApprove} onReject={handleReject} />
          {run && (
            <RemediationPanel
              canSync={Boolean(run)}
              onSync={() => api.syncDefectDojo(run.id)}
              onError={showToast}
            />
          )}
        </div>
      </div>
      <Toast message={message} />
    </main>
  );
}
