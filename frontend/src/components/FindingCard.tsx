import { useState, type MouseEvent } from "react";
import type { Finding } from "../types";
import { CodeBlock } from "./CodeBlock";
import { severityColor } from "../lib/severityColor";
import { formatAge, firstSentence } from "../lib/format";

interface FindingCardProps {
  finding: Finding;
  expanded: boolean;
  onToggle: () => void;
  onApprove: (finding: Finding) => Promise<void>;
  onReject: (finding: Finding) => Promise<void>;
}

function VerificationBadge({ finding }: { finding: Finding }) {
  if (finding.verified === true) {
    return (
      <span className="stamp" style={{ color: "var(--status-good-text)" }}>
        <span className="stamp-dot" />
        Verified in sandbox
      </span>
    );
  }
  if (finding.verified === false) {
    return (
      <span className="stamp" style={{ color: "var(--status-warning)" }}>
        <span className="stamp-dot" />
        Not reproduced
      </span>
    );
  }
  return (
    <span className="stamp" style={{ color: "var(--ink-muted)" }}>
      <span className="stamp-dot" />
      Unverified
    </span>
  );
}

function VerdictStamp({ finding }: { finding: Finding }) {
  if (finding.verdict === "false_positive") {
    return (
      <span className="stamp" style={{ color: "var(--status-good-text)" }}>
        <span className="stamp-dot" />
        Cleared
      </span>
    );
  }
  if (finding.approval_status === "approved") {
    return (
      <span className="stamp" style={{ color: "var(--accent)" }}>
        <span className="stamp-dot" />
        Fix approved
      </span>
    );
  }
  if (finding.approval_status === "rejected") {
    return (
      <span className="stamp" style={{ color: "var(--ink-muted)" }}>
        <span className="stamp-dot" />
        Not a vulnerability — reviewed
      </span>
    );
  }
  const color = severityColor(finding.severity);
  return (
    <span className="stamp" style={{ color }}>
      <span className="stamp-dot" />
      Confirmed
    </span>
  );
}

export function FindingCard({ finding, expanded, onToggle, onApprove, onReject }: FindingCardProps) {
  const [approving, setApproving] = useState(false);
  const [rejecting, setRejecting] = useState(false);
  const confidencePct = Math.round((finding.confidence || 0) * 100);
  const rejected = finding.approval_status === "rejected";

  const handleApprove = async (e: MouseEvent) => {
    e.stopPropagation();
    setApproving(true);
    try {
      await onApprove(finding);
    } finally {
      setApproving(false);
    }
  };

  const handleReject = async (e: MouseEvent) => {
    e.stopPropagation();
    setRejecting(true);
    try {
      await onReject(finding);
    } finally {
      setRejecting(false);
    }
  };

  return (
    <div
      className="rise-in surface overflow-hidden rounded-lg"
      style={{
        borderLeft: `3px solid ${rejected ? "var(--border)" : severityColor(finding.severity)}`,
        opacity: rejected ? 0.55 : 1,
      }}
    >
      <button
        type="button"
        onClick={onToggle}
        className="flex w-full cursor-pointer items-center gap-3 border-none bg-transparent px-5 py-4 text-left"
      >
        <span
          className="ink-muted flex-none text-xs transition-transform duration-150"
          style={{ transform: expanded ? "rotate(90deg)" : "none" }}
        >
          ▸
        </span>
        <div className="min-w-0 flex-1">
          <div className="truncate text-[0.86rem] font-medium">
            {firstSentence(finding.message, finding.rule_id)}
          </div>
          <div className="font-mono ink-muted truncate text-[0.72rem]">
            {finding.repo}/{finding.file}:{finding.line}
          </div>
        </div>
        {finding.dedup_group_id && (
          <span
            className="font-mono hidden shrink-0 rounded-full border px-2 py-0.5 text-[0.74rem] sm:inline-block"
            style={{ borderColor: "var(--gold)", color: "var(--gold)" }}
            title="Same vulnerability class merged across repos"
          >
            {finding.is_dedup_primary ? "dedup primary" : "dedup dup"}
          </span>
        )}
        {finding.sla_breached && (
          <span
            className="font-mono hidden shrink-0 rounded-full border px-2 py-0.5 text-[0.74rem] sm:inline-block"
            style={{ borderColor: "var(--status-warning)", color: "var(--status-warning)" }}
          >
            ⏱ SLA {formatAge(finding.age_seconds)}
          </span>
        )}
        <VerdictStamp finding={finding} />
      </button>

      {expanded && (
        <div className="grid grid-cols-1 gap-6 border-t px-5 py-6 lg:grid-cols-2" style={{ borderColor: "var(--border)" }}>
          <div>
            <h4 className="ink-secondary mb-1.5 text-[0.72rem] font-semibold tracking-wide uppercase">Code</h4>
            <CodeBlock code={finding.code_snippet} />
          </div>

          <div>
            <h4 className="ink-secondary mb-1.5 flex items-center gap-2 text-[0.72rem] font-semibold tracking-wide uppercase">
              Analyst rationale
              <span className="h-1 flex-1 max-w-16 rounded-full" style={{ background: "var(--gridline)" }}>
                <span
                  className="block h-full rounded-full"
                  style={{ width: `${confidencePct}%`, background: "var(--gold)" }}
                />
              </span>
              <span className="tabular normal-case">{confidencePct}%</span>
            </h4>
            <p className="ink-primary text-[0.82rem] leading-relaxed">
              {finding.rationale || "Not yet validated."}
            </p>
          </div>

          {finding.poc && (
            <div className="lg:col-span-2">
              <div className="mb-1.5 flex flex-wrap items-center gap-2">
                <h4 className="ink-secondary text-[0.72rem] font-semibold tracking-wide uppercase">
                  Proof of concept
                </h4>
                <VerificationBadge finding={finding} />
              </div>
              <pre className="font-mono surface m-0 overflow-x-auto rounded-md p-3 text-[0.76rem] leading-relaxed" style={{ background: "var(--page)" }}>
                {finding.poc}
              </pre>
              {finding.poc_explanation && (
                <p className="ink-secondary mt-1.5 text-[0.76rem]">{finding.poc_explanation}</p>
              )}
              {finding.verification_detail && (
                <p className="ink-secondary mt-1.5 text-[0.76rem]">{finding.verification_detail}</p>
              )}
            </div>
          )}

          {finding.verdict === "confirmed" && (
            <div className="flex items-center gap-3 lg:col-span-2">
              {finding.approval_status === "awaiting_approval" && (
                <>
                  <button
                    type="button"
                    onClick={handleApprove}
                    disabled={approving || rejecting}
                    className="cursor-pointer rounded-md border-none px-3.5 py-2 text-[0.8rem] font-semibold disabled:cursor-not-allowed disabled:opacity-60"
                    style={{ background: "var(--brand)", color: "var(--brand-ink)" }}
                  >
                    {approving ? "Generating fix…" : "Approve & generate fix"}
                  </button>
                  <button
                    type="button"
                    onClick={handleReject}
                    disabled={approving || rejecting}
                    className="cursor-pointer rounded-md px-3.5 py-2 text-[0.8rem] font-semibold disabled:cursor-not-allowed disabled:opacity-60"
                    style={{ background: "transparent", color: "var(--ink-secondary)", border: "1.5px solid var(--border-strong)" }}
                  >
                    {rejecting ? "Marking…" : "Not a vulnerability"}
                  </button>
                  <span className="ink-muted text-[0.74rem]">
                    Human approval required before any fix is generated or applied.
                  </span>
                </>
              )}
              {finding.approval_status === "approved" && (
                <span className="stamp" style={{ color: "var(--accent)" }}>
                  <span className="stamp-dot" />
                  Approved by human reviewer
                </span>
              )}
              {rejected && (
                <span className="stamp" style={{ color: "var(--ink-muted)" }}>
                  <span className="stamp-dot" />
                  Not a vulnerability — reviewed
                </span>
              )}
            </div>
          )}

          {finding.fix_patch && (
            <div className="lg:col-span-2">
              <h4 className="ink-secondary mb-1.5 text-[0.72rem] font-semibold tracking-wide uppercase">
                Suggested fix
              </h4>
              <pre className="font-mono surface m-0 overflow-x-auto rounded-md p-3 text-[0.76rem] leading-relaxed" style={{ background: "var(--page)" }}>
                {finding.fix_patch}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
