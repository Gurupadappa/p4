"""Scan stage: run Semgrep with our pattern rules against a prepared repo to
produce candidate findings. This is intentionally the same "cast a wide net"
behavior a baseline pattern-matching SAST tool would exhibit — precision is
the Validate stage's job, not this one.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

from .models import Finding, ValidationVerdict, new_id

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
TAG_RE = re.compile(r"---\s*([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+)")
CONTEXT_LINES = 3

# Our own hand-written rules stay first (they carry the vuln_class/cwe metadata
# our demo cases key off of). The registry rulesets bolt on broad, community-
# maintained coverage (XSS, path traversal, secrets, crypto, IDOR-shaped
# patterns, etc.) that would otherwise take months to hand-roll.
SEMGREP_CONFIGS = [
    str(RULES_DIR),
    "p/security-audit",
    "p/secrets",
    "p/owasp-top-ten",
]


def _nearest_tag_above(lines: list[str], line_no: int) -> str | None:
    start = max(0, line_no - 1 - 15)
    for i in range(line_no - 1, start - 1, -1):
        m = TAG_RE.search(lines[i])
        if m:
            return m.group(1)
    return None


def _vuln_class(metadata: dict) -> str:
    """Our own rules tag `vuln_class` directly. Semgrep registry rules instead
    carry a human-readable `vulnerability_class` list (e.g. ["SQL Injection"]) -
    slugify the first entry so both sources end up in the same shape.
    """
    own = metadata.get("vuln_class")
    if own:
        return own
    registry = metadata.get("vulnerability_class") or []
    if registry:
        return re.sub(r"[^a-z0-9]+", "_", registry[0].strip().lower()).strip("_")
    return "unknown"


def _snippet(lines: list[str], line_no: int) -> str:
    start = max(0, line_no - 1 - CONTEXT_LINES)
    end = min(len(lines), line_no + CONTEXT_LINES)
    out = []
    for i in range(start, end):
        marker = ">>" if i == line_no - 1 else "  "
        out.append(f"{marker} {i + 1:>4}| {lines[i]}")
    return "\n".join(out)


SEMGREP_BIN = shutil.which("semgrep") or "semgrep"


def run_semgrep(repo_path: str, baseline_commit: str | None = None) -> dict:
    config_args = [arg for cfg in SEMGREP_CONFIGS for arg in ("--config", cfg)]
    # Diff-aware scanning: only report findings not already present at this
    # commit, so dropping P4 into a legacy repo doesn't fail every PR on
    # pre-existing findings nobody triaged yet. Requires repo_path to be a
    # clean git working directory with baseline_commit reachable locally.
    # Semgrep resolves the baseline commit via `git cat-file` in the process's
    # *current working directory*, not the scan target argument - so cwd must
    # be repo_path or a baseline lookup silently fails and comes back as an
    # empty result set (checked below) instead of an error.
    baseline_args = ["--baseline-commit", baseline_commit] if baseline_commit else []
    proc = subprocess.run(
        [
            SEMGREP_BIN,
            "scan",
            *config_args,
            *baseline_args,
            "--json",
            "--quiet",
            "--metrics=off",
            ".",
        ],
        cwd=repo_path,
        capture_output=True,
        text=True,
        timeout=300,
    )
    if not proc.stdout.strip():
        raise RuntimeError(f"semgrep produced no output: {proc.stderr[-2000:]}")
    raw = json.loads(proc.stdout)
    fatal = [e for e in raw.get("errors", []) if e.get("level") == "error"]
    if fatal:
        raise RuntimeError(f"semgrep reported fatal error(s): {json.dumps(fatal)}")
    return raw


def scan_repo(
    run_id: str, repo_name: str, repo_path: str, baseline_commit: str | None = None
) -> list[Finding]:
    raw = run_semgrep(repo_path, baseline_commit)
    root = Path(repo_path)
    findings: list[Finding] = []

    file_cache: dict[str, list[str]] = {}

    for result in raw.get("results", []):
        rel_path = result["path"]
        # Semgrep runs with cwd=repo_path (see run_semgrep), so paths in its
        # output are relative to repo_path, not to our own process cwd.
        file_path = Path(rel_path)
        if not file_path.is_absolute():
            file_path = root / file_path
        if rel_path not in file_cache:
            try:
                file_cache[rel_path] = (
                    file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
                )
            except OSError:
                file_cache[rel_path] = []
        lines = file_cache[rel_path]
        line_no = result["start"]["line"]

        rel_display = str(file_path.relative_to(root)).replace("\\", "/")

        findings.append(
            Finding(
                id=new_id("f"),
                run_id=run_id,
                repo=repo_name,
                file=rel_display,
                line=line_no,
                rule_id=result["check_id"].split(".")[-1],
                vuln_class=_vuln_class(result.get("extra", {}).get("metadata", {})),
                severity=result.get("extra", {}).get("severity", "WARNING"),
                message=result.get("extra", {}).get("message", "").strip(),
                code_snippet=_snippet(lines, line_no) if lines else "",
                ground_truth_tag=_nearest_tag_above(lines, line_no) if lines else None,
                verdict=ValidationVerdict.PENDING,
            )
        )

    return findings
