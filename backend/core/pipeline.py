"""Orchestrates the four-stage Prepare -> Scan -> Validate -> Prove pipeline,
persisting state after every stage so the UI can show live progress.
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

# Backdated for the SLA-breach demo: these two, if confirmed, are made to
# look like they've been sitting unresolved for >72h.
SLA_DEMO_TAGS = {"FLASK-DESER-1", "EXPRESS-SQLI-1"}
SLA_BACKDATE_SECONDS = 100 * 3600


def run_pipeline(run_id: str, repo_paths: dict[str, str]) -> None:
    run = PipelineRun(id=run_id, repos=list(repo_paths.keys()))
    store.save_run(run)

    try:
        # --- Prepare ---
        run.stage = Stage.PREPARE
        store.save_run(run)
        cpg_by_repo = {name: prepare_repo(name, path) for name, path in repo_paths.items()}

        # --- Scan ---
        run.stage = Stage.SCAN
        store.save_run(run)
        findings = []
        for name, path in repo_paths.items():
            findings.extend(scan_repo(run_id, name, path))
        store.save_findings(findings)

        # --- Validate (+ cross-repo dedup) ---
        run.stage = Stage.VALIDATE
        store.save_run(run)
        validate_findings(findings, cpg_by_repo)
        dedupe_findings(findings)
        store.save_findings(findings)

        # --- Prove (+ real sandboxed verification, best-effort) ---
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
    except Exception as exc:  # noqa: BLE001 - surface any stage failure to the UI
        run.error = str(exc)
        run.finished_at = time.time()
        store.save_run(run)
        raise


def approve_and_fix(finding_id: str) -> None:
    """Human-approval gate: only after this is called does a fix get generated."""
    finding = store.get_finding(finding_id)
    if finding is None:
        raise ValueError(f"unknown finding {finding_id}")
    finding.approval_status = ApprovalStatus.APPROVED
    generate_fix(finding)
    store.save_finding(finding)


def reject_finding(finding_id: str) -> None:
    """Human-review gate: reviewer marked this finding as not a vulnerability. No fix is generated."""
    finding = store.get_finding(finding_id)
    if finding is None:
        raise ValueError(f"unknown finding {finding_id}")
    finding.approval_status = ApprovalStatus.REJECTED
    store.save_finding(finding)


def new_run_id() -> str:
    return new_id("run")
