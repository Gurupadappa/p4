import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../lib/api";
import type { Finding, PipelineRun, Report } from "../types";

const POLL_INTERVAL_MS = 1400;

export function useScanRun(onError: (message: string) => void) {
  const [run, setRun] = useState<PipelineRun | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [report, setReport] = useState<Report | null>(null);
  const [starting, setStarting] = useState(false);
  const pollTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  useEffect(() => () => clearTimeout(pollTimer.current), []);

  const poll = useCallback(
    (runId: string) => {
      clearTimeout(pollTimer.current);
      pollTimer.current = setTimeout(async () => {
        try {
          const next = await api.getRun(runId);
          setRun(next);
          if (next.stage === "done" || next.error) {
            const [findingsRes, reportRes] = await Promise.all([
              api.getFindings(runId),
              api.getReport(runId),
            ]);
            setFindings(findingsRes.findings);
            setReport(reportRes);
            return;
          }
          poll(runId);
        } catch (e) {
          onError(`Polling error: ${(e as Error).message}`);
        }
      }, POLL_INTERVAL_MS);
    },
    [onError],
  );

  const startScan = useCallback(
    async (repos: string[]) => {
      setStarting(true);
      try {
        const { run_id } = await api.startScan(repos);
        setFindings([]);
        setReport(null);
        setRun({ id: run_id, repos, stage: "prepare", started_at: Date.now() / 1000, finished_at: null, error: null });
        poll(run_id);
      } catch (e) {
        onError(`Failed to start scan: ${(e as Error).message}`);
      } finally {
        setStarting(false);
      }
    },
    [poll, onError],
  );

  const applyFindingUpdate = useCallback((updated: Finding) => {
    setFindings((current) => current.map((f) => (f.id === updated.id ? updated : f)));
  }, []);

  const running = run !== null && run.stage !== "done" && !run.error;

  return { run, findings, report, starting, running, startScan, applyFindingUpdate };
}
