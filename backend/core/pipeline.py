"""Coordinates the four-step Prepare -> Scan -> Validate -> Prove workflow,
saving the pipeline state after each step so the UI can display progress in real time.
"""

from __future__ import annotations

import time

from . import store
from .dedupe import dedupe_findings
from .models import ApprovalStatus, PipelineRun, Stage, ValidationVerdict, new_id
from .prepare import prepare_repo
from .prove import generate_fix, prove_findings
from .scan import scan_repo
from .validate import validate_findings
from .verify import verify_findings

# Used for the SLA demonstration: when these findings are confirmed,
# their timestamps are adjusted to simulate unresolved findings older than 72 hours.
SLA_DEMO_TAGS = {"FLASK-DESER-1", "EXPRESS-SQLI-1"}
SLA_BACKDATE_SECONDS = 100 * 3600


def run_pipeline(run_id: str, repo_paths: dict[str, str]) -> None:
    run = PipelineRun(id=run_id, repos=list(repo_paths.keys()))
    store.save_run(run)

    try:
        # --- Repository Preparation ---
        run.stage = Stage.PREPARE
        store.save_run(run)
        cpg_by_repo = {name: prepare_repo(name, path) for name, path in repo_paths.items()}

        # --- Repository Scanning ---
        run.stage = Stage.SCAN
        store.save_run(run)
        findings = []
        for name, path in repo_paths.items():
            findings.extend(scan_repo(run_id, name, path))
        store.save_findings(findings)

        # --- Finding Validation and Cross-Repository Deduplication ---
        run.stage = Stage.VALIDATE
        store.save_run(run)
        validate_findings(findings, cpg_by_repo)
        dedupe_findings(findings)
        store.save_findings(findings)

        # --- Finding Proof and Best-Effort Sandbox Verification ---
        run.stage = Stage.PROVE
        store.save_run(run)
        prove_findings(findings)
        verify_findings(findings)
        for f in findings:
            if f.verdict == ValidationVerdict.CONFIRMED:
                f.approval_status = ApprovalStatus.AWAITING_APPROVAL
                if f.ground_truth_tag in SLA_DEMO_TAGS:
                    f.first_seen = time.time() - SLA_BACKDATE_SECONDS
        store.save_findings(findings)

        run.stage = Stage.DONE
        run.finished_at = time.time()
        store.save_run(run)
    except Exception as exc:  # noqa: BLE001 - make stage errors visible to the UI
        run.error = str(exc)
        run.finished_at = time.time()
        store.save_run(run)
        raise


def approve_and_fix(finding_id: str) -> None:
    """Generates a fix only after the finding receives explicit human approval."""
    finding = store.get_finding(finding_id)
    if finding is None:
        raise ValueError(f"unknown finding {finding_id}")
    finding.approval_status = ApprovalStatus.APPROVED
    generate_fix(finding)
    store.save_finding(finding)


def reject_finding(finding_id: str) -> None:
    """Records a reviewer's rejection of the finding without generating a fix."""
    finding = store.get_finding(finding_id)
    if finding is None:
        raise ValueError(f"unknown finding {finding_id}")
    finding.approval_status = ApprovalStatus.REJECTED
    store.save_finding(finding)


def new_run_id() -> str:
    return new_id("run")
