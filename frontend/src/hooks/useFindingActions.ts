import { useCallback } from "react";
import { api } from "../lib/api";
import type { Finding } from "../types";

export function useFindingActions(
  applyFindingUpdate: (updated: Finding) => void,
  showToast: (message: string) => void,
) {
  const handleApprove = useCallback(
    async (finding: Finding) => {
      try {
        const updated = await api.approveFinding(finding.id);
        applyFindingUpdate(updated);
        showToast("Fix approved and generated");
      } catch (e) {
        showToast(`Approval failed: ${(e as Error).message}`);
      }
    },
    [applyFindingUpdate, showToast],
  );

  const handleReject = useCallback(
    async (finding: Finding) => {
      try {
        const updated = await api.rejectFinding(finding.id);
        applyFindingUpdate(updated);
        showToast("Marked as not a vulnerability");
      } catch (e) {
        showToast(`Reject failed: ${(e as Error).message}`);
      }
    },
    [applyFindingUpdate, showToast],
  );

  return { handleApprove, handleReject };
}
