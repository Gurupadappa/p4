from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from backend.core import scan as scan_module
from backend.core.models import ValidationVerdict


def _fake_semgrep_result(file_path: str, line: int) -> dict:
    return {
        "results": [
            {
                "check_id": "python-taint-rules.python-os-system-call",
                "path": file_path,
                "start": {"line": line},
                "extra": {
                    "severity": "ERROR",
                    "message": "os.system() executes a string in a shell.",
                    "metadata": {"vuln_class": "injection"},
                },
            }
        ]
    }

def test_scan_repo_detects_sql_injection_and_extracts_ground_truth_tag(tmp_path, monkeypatch):
    target = tmp_path / "app.py"
    target.write_text(
        "from flask import request\n"
        "import sqlite3\n\n"
        "# --- FLASK-SQLI-1 ---\n"
        "def search():\n"
        "    customer = request.args.get('customer')\n"
        "    query = \"SELECT * FROM users WHERE name = '\" + customer + \"'\"\n"
        "    conn = sqlite3.connect('test.db')\n"
        "    conn.execute(query)\n",
        encoding="utf-8",
    )

    raw = {
        "results": [
            {
                "check_id": "python-taint-rules.python-sql-injection",
                "path": str(target),
                "start": {"line": 7},
                "extra": {
                    "severity": "ERROR",
                    "message": "User input is used in a SQL query.",
                    "metadata": {"vuln_class": "injection"},
                },
            }
        ]
    }

    def fake_run(*args, **kwargs):
        return SimpleNamespace(
            stdout=json.dumps(raw),
            stderr="",
            returncode=0,
        )

    monkeypatch.setattr(scan_module.subprocess, "run", fake_run)

    findings = scan_module.scan_repo("run_1", "vuln_flask_api", str(tmp_path))

    assert len(findings) == 1

    f = findings[0]

    assert f.repo == "vuln_flask_api"
    assert f.rule_id == "python-sql-injection"
    assert f.vuln_class == "injection"
    assert f.severity == "ERROR"
    assert f.verdict == ValidationVerdict.PENDING
    assert f.ground_truth_tag == "FLASK-SQLI-1"
    assert ">>" in f.code_snippet
def test_scan_repo_parses_finding_and_extracts_ground_truth_tag(tmp_path, monkeypatch):
    target = tmp_path / "app.py"
    target.write_text(
        "import os\n\n# --- FLASK-CMDI-1 ---\ndef run(cmd):\n    os.system(cmd)\n",
        encoding="utf-8",
    )
    vulnerable_line = 5  # os.system(cmd)

    raw = _fake_semgrep_result(str(target), vulnerable_line)

    def fake_run(*args, **kwargs):
        return SimpleNamespace(stdout=json.dumps(raw), stderr="", returncode=0)

    monkeypatch.setattr(scan_module.subprocess, "run", fake_run)

    findings = scan_module.scan_repo("run_1", "demo_repo", str(tmp_path))

    assert len(findings) == 1
    f = findings[0]
    assert f.repo == "demo_repo"
    assert f.line == vulnerable_line
    assert f.rule_id == "python-os-system-call"
    assert f.vuln_class == "injection"
    assert f.severity == "ERROR"
    assert f.verdict == ValidationVerdict.PENDING
    assert f.ground_truth_tag == "FLASK-CMDI-1"
    assert ">>" in f.code_snippet


def test_scan_repo_raises_on_empty_semgrep_output(monkeypatch):
    def fake_run(*args, **kwargs):
        return SimpleNamespace(stdout="", stderr="semgrep exploded", returncode=1)

    monkeypatch.setattr(scan_module.subprocess, "run", fake_run)

    with pytest.raises(RuntimeError, match="semgrep"):
        scan_module.scan_repo("run_1", "demo_repo", ".")


def test_scan_repo_returns_empty_list_when_no_results(tmp_path, monkeypatch):
    def fake_run(*args, **kwargs):
        return SimpleNamespace(stdout=json.dumps({"results": []}), stderr="", returncode=0)

    monkeypatch.setattr(scan_module.subprocess, "run", fake_run)

    findings = scan_module.scan_repo("run_1", "demo_repo", str(tmp_path))
    assert findings == []


def test_run_semgrep_omits_baseline_flag_by_default(monkeypatch):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return SimpleNamespace(stdout=json.dumps({"results": []}), stderr="", returncode=0)

    monkeypatch.setattr(scan_module.subprocess, "run", fake_run)

    scan_module.run_semgrep(".")
    assert "--baseline-commit" not in captured["cmd"]


def test_run_semgrep_passes_baseline_commit_when_given(monkeypatch):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return SimpleNamespace(stdout=json.dumps({"results": []}), stderr="", returncode=0)

    monkeypatch.setattr(scan_module.subprocess, "run", fake_run)

    scan_module.run_semgrep(".", baseline_commit="abc123")
    assert "--baseline-commit" in captured["cmd"]
    idx = captured["cmd"].index("--baseline-commit")
    assert captured["cmd"][idx + 1] == "abc123"
