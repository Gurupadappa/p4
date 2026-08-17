"""DefectDojo integration adapter for remediation ticket workflows.

Formats confirmed findings into DefectDojo's Generic Finding Import JSON
schema. POSTs to a real DefectDojo instance if DEFECTDOJO_URL /
DEFECTDOJO_API_KEY are configured; otherwise writes the payload to disk so
the "would sync" behavior is still demonstrable without a live instance.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import requests

from .models import Finding, ValidationVerdict
from .severity import normalize

SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "n/a": "Info",
}

OUT_DIR = Path(__file__).resolve().parent.parent.parent / "run_artifacts"


def _to_generic_finding(f: Finding) -> dict:
    tags = [f.vuln_class, f.repo, f.rule_id]
    if f.dedup_group_id:
        # DefectDojo's Generic Findings Import schema rejects a `duplicate`
        # field outright (verified against a live instance), so cross-repo
        # dedup grouping is carried as tags instead of a first-class field.
        tags.append(f"dedup-{f.dedup_group_id}")
        tags.append("dedup-primary" if f.is_dedup_primary else "dedup-secondary")
    finding = {
        "title": f"[{f.vuln_class}] {f.rule_id} in {f.repo}/{f.file}:{f.line}",
        "description": f.message or "No scanner message.",
        "severity": SEVERITY_MAP.get(normalize(f.severity), "Medium"),
        "file_path": f.file,
        "line": f.line,
        "cwe": 0,
        # No `date` key at all: DefectDojo's generic parser unconditionally
        # runs dateutil.parser.parse() on this field when the key is
        # present, even if the value is null, and 500s.
        "active": True,
        "verified": True,
        "false_p": False,
        "tags": tags,
    }
    # Map P4's own stage outputs onto DefectDojo's dedicated fields instead
    # of concatenating everything into `description` — only set a key when
    # the content actually exists, since a stage that hasn't run yet
    # (Prove skipped, fix not yet approved) leaves these fields empty.
    if f.rationale:
        finding["severity_justification"] = f.rationale
    if f.poc:
        finding["steps_to_reproduce"] = f.poc
    if f.poc_explanation:
        finding["impact"] = f.poc_explanation
    if f.fix_patch:
        finding["mitigation"] = f.fix_patch
    return finding


def build_import_payload(findings: list[Finding]) -> dict:
    confirmed = [f for f in findings if f.verdict == ValidationVerdict.CONFIRMED]
    return {"findings": [_to_generic_finding(f) for f in confirmed]}


def sync_to_defectdojo(run_id: str, findings: list[Finding]) -> dict:
    payload = build_import_payload(findings)
    url = os.environ.get("DEFECTDOJO_URL")
    api_key = os.environ.get("DEFECTDOJO_API_KEY")

    if url and api_key:
        # /api/v2/import-scan/ only accepts multipart/form-data (a plain
        # JSON body 415s) and needs a product/engagement to attach the scan
        # to. auto_create_context=true creates them on first sync instead of
        # requiring them to be pre-provisioned through the DefectDojo UI.
        resp = requests.post(
            f"{url.rstrip('/')}/api/v2/import-scan/",
            headers={"Authorization": f"Token {api_key}"},
            data={
                "scan_type": "Generic Findings Import",
                "product_name": "P4",
                "engagement_name": f"P4 run {run_id}",
                "product_type_name": "Research and Development",
                "auto_create_context": "true",
            },
            files={"file": (f"{run_id}.json", json.dumps(payload), "application/json")},
            timeout=30,
        )
        resp.raise_for_status()
        return {"synced": True, "target": url, "count": len(payload["findings"])}

    OUT_DIR.mkdir(exist_ok=True)
    out_path = OUT_DIR / f"{run_id}_defectdojo_import.json"
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return {
        "synced": False,
        "would_sync_count": len(payload["findings"]),
        "artifact_path": str(out_path),
        "note": "DEFECTDOJO_URL/DEFECTDOJO_API_KEY not configured — payload written to disk instead.",
    }
