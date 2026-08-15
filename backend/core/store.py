"""Lightweight SQLite persistence for pipeline runs and findings.

Findings are stored as JSON blobs (the analysis logic lives in Python
dataclasses, not in SQL) but are still queryable by run_id and are durable
across process restarts.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

from .models import (
    ApprovalStatus,
    Finding,
    PipelineRun,
    Stage,
    ValidationVerdict,
)

DB_PATH = Path(__file__).resolve().parent.parent.parent / "run_artifacts" / "sast_engine.db"
_lock = threading.Lock()


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS runs (
            id TEXT PRIMARY KEY, repos TEXT, stage TEXT,
            started_at REAL, finished_at REAL, error TEXT
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY, run_id TEXT, data TEXT
        )"""
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id)")
    return conn


_conn = _connect()


def save_run(run: PipelineRun) -> None:
    with _lock:
        _conn.execute(
            "INSERT OR REPLACE INTO runs VALUES (?, ?, ?, ?, ?, ?)",
            (
                run.id,
                json.dumps(run.repos),
                run.stage.value,
                run.started_at,
                run.finished_at,
                run.error,
            ),
        )
        _conn.commit()


def get_run(run_id: str) -> PipelineRun | None:
    row = _conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
    if not row:
        return None
    return PipelineRun(
        id=row[0],
        repos=json.loads(row[1]),
        stage=Stage(row[2]),
        started_at=row[3],
        finished_at=row[4],
        error=row[5],
    )


def list_runs() -> list[PipelineRun]:
    rows = _conn.execute("SELECT * FROM runs ORDER BY started_at DESC").fetchall()
    return [
        PipelineRun(
            id=r[0],
            repos=json.loads(r[1]),
            stage=Stage(r[2]),
            started_at=r[3],
            finished_at=r[4],
            error=r[5],
        )
        for r in rows
    ]


def _finding_from_row(data: dict) -> Finding:
    data = dict(data)
    data["verdict"] = ValidationVerdict(data["verdict"])
    data["approval_status"] = ApprovalStatus(data["approval_status"])
    data.pop("age_seconds", None)
    data.pop("sla_breached", None)
    return Finding(**data)


def save_findings(findings: list[Finding]) -> None:
    with _lock:
        for f in findings:
            _conn.execute(
                "INSERT OR REPLACE INTO findings VALUES (?, ?, ?)",
                (f.id, f.run_id, json.dumps(f.to_dict())),
            )
        _conn.commit()


def save_finding(finding: Finding) -> None:
    save_findings([finding])


def get_finding(finding_id: str) -> Finding | None:
    row = _conn.execute("SELECT data FROM findings WHERE id = ?", (finding_id,)).fetchone()
    if not row:
        return None
    return _finding_from_row(json.loads(row[0]))


def list_findings(run_id: str) -> list[Finding]:
    rows = _conn.execute("SELECT data FROM findings WHERE run_id = ?", (run_id,)).fetchall()
    return [_finding_from_row(json.loads(r[0])) for r in rows]


def run_summary(run_id: str) -> dict:
    findings = list_findings(run_id)
    return {
        "total": len(findings),
        "confirmed": sum(1 for f in findings if f.verdict == ValidationVerdict.CONFIRMED),
        "false_positive": sum(1 for f in findings if f.verdict == ValidationVerdict.FALSE_POSITIVE),
        "awaiting_approval": sum(1 for f in findings if f.approval_status == ApprovalStatus.AWAITING_APPROVAL),
        "approved": sum(1 for f in findings if f.approval_status == ApprovalStatus.APPROVED),
        "rejected": sum(1 for f in findings if f.approval_status == ApprovalStatus.REJECTED),
    }
