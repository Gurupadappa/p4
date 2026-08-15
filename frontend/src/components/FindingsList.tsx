import { useMemo, useState } from "react";
import type { Finding } from "../types";
import { FindingCard } from "./FindingCard";

type Filter = "all" | "confirmed" | "awaiting_approval" | "approved" | "rejected" | "false_positive";

const FILTERS: Array<{ key: Filter; label: string }> = [
  { key: "all", label: "All" },
  { key: "confirmed", label: "Confirmed" },
  { key: "awaiting_approval", label: "Awaiting approval" },
  { key: "approved", label: "Approved" },
  { key: "rejected", label: "Not a vulnerability" },
  { key: "false_positive", label: "Suppressed FPs" },
];

function matches(f: Finding, filter: Filter): boolean {
  switch (filter) {
    case "confirmed":
      return f.verdict === "confirmed";
    case "false_positive":
      return f.verdict === "false_positive";
    case "awaiting_approval":
      return f.approval_status === "awaiting_approval";
    case "approved":
      return f.approval_status === "approved";
    case "rejected":
      return f.approval_status === "rejected";
    default:
      return true;
  }
}

interface FindingsListProps {
  findings: Finding[];
  onApprove: (finding: Finding) => Promise<void>;
  onReject: (finding: Finding) => Promise<void>;
}

export function FindingsList({ findings, onApprove, onReject }: FindingsListProps) {
  const [filter, setFilter] = useState<Filter>("all");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const sorted = useMemo(() => {
    return findings
      .filter((f) => matches(f, filter))
      .slice()
      .sort((a, b) => {
        const aRejected = a.approval_status === "rejected";
        const bRejected = b.approval_status === "rejected";
        if (aRejected !== bRejected) return aRejected ? 1 : -1;
        if (a.sla_breached !== b.sla_breached) return a.sla_breached ? -1 : 1;
        const aConfirmed = a.verdict === "confirmed";
        const bConfirmed = b.verdict === "confirmed";
        if (aConfirmed !== bConfirmed) return aConfirmed ? -1 : 1;
        return a.file.localeCompare(b.file) || a.line - b.line;
      });
  }, [findings, filter]);

  const toggle = (id: string) => {
    setExpanded((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  return (
    <section>
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <h2 className="font-display m-0 text-base font-semibold">Findings</h2>
        <div className="flex flex-wrap gap-1.5" role="group" aria-label="Filter findings">
          {FILTERS.map(({ key, label }) => {
            const active = filter === key;
            return (
              <button
                key={key}
                type="button"
                onClick={() => setFilter(key)}
                className="font-mono cursor-pointer rounded-full border px-3 py-1 text-[0.72rem] transition-colors"
                style={{
                  borderColor: active ? "var(--gold)" : "var(--border)",
                  background: active ? "var(--accent-wash)" : "transparent",
                  color: active ? "var(--gold)" : "var(--ink-secondary)",
                }}
              >
                {label}
              </button>
            );
          })}
        </div>
      </div>

      {!findings.length && (
        <div className="surface ink-muted rounded-lg px-5 py-8 text-center text-[0.84rem]">
          No findings yet. Run a scan to populate this console.
        </div>
      )}
      {findings.length > 0 && !sorted.length && (
        <div className="surface ink-muted rounded-lg px-5 py-8 text-center text-[0.84rem]">
          No findings match this filter.
        </div>
      )}

      <div className="flex flex-col gap-3">
        {sorted.map((f) => (
          <FindingCard
            key={f.id}
            finding={f}
            expanded={expanded.has(f.id)}
            onToggle={() => toggle(f.id)}
            onApprove={onApprove}
            onReject={onReject}
          />
        ))}
      </div>
    </section>
  );
}
