from __future__ import annotations

import json

from backend import cli
from backend.core.models import ValidationVerdict


def _stub_pipeline(monkeypatch, findings_by_call):
    """Replace prepare/scan/validate/dedupe/prove with stubs so no real
    semgrep binary or LLM call is needed. `findings_by_call` is mutated
    in place by the fake validate step to set verdicts."""
    monkeypatch.setattr(cli, "prepare_repo", lambda name, path: object())
    monkeypatch.setattr(
        cli, "scan_repo", lambda run_id, name, path, baseline_commit=None: list(findings_by_call)
    )
    monkeypatch.setattr(cli, "validate_findings", lambda findings, cpg_by_repo: findings)
    monkeypatch.setattr(cli, "dedupe_findings", lambda findings: findings)
    monkeypatch.setattr(cli, "prove_findings", lambda findings: findings)


def test_scan_exits_1_when_confirmed_finding(tmp_path, monkeypatch, make_finding, capsys):
    f = make_finding(verdict=ValidationVerdict.CONFIRMED, severity="ERROR")
    _stub_pipeline(monkeypatch, [f])

    code = cli.main(["scan", str(tmp_path)])

    assert code == 1
    assert "FAIL" in capsys.readouterr().err


def test_scan_exits_0_when_no_confirmed_findings(tmp_path, monkeypatch, make_finding):
    f = make_finding(verdict=ValidationVerdict.FALSE_POSITIVE)
    _stub_pipeline(monkeypatch, [f])

    assert cli.main(["scan", str(tmp_path)]) == 0


def test_scan_fail_on_none_always_passes(tmp_path, monkeypatch, make_finding):
    f = make_finding(verdict=ValidationVerdict.CONFIRMED)
    _stub_pipeline(monkeypatch, [f])

    assert cli.main(["scan", str(tmp_path), "--fail-on", "none"]) == 0


def test_scan_skip_validate_always_passes(tmp_path, monkeypatch, make_finding):
    f = make_finding(verdict=ValidationVerdict.CONFIRMED)  # would fail if validate ran
    _stub_pipeline(monkeypatch, [f])

    assert cli.main(["scan", str(tmp_path), "--skip-validate"]) == 0


def test_scan_min_severity_filters_out_low_severity_confirmed(tmp_path, monkeypatch, make_finding):
    f = make_finding(verdict=ValidationVerdict.CONFIRMED, severity="INFO")
    _stub_pipeline(monkeypatch, [f])

    assert cli.main(["scan", str(tmp_path), "--min-severity", "high"]) == 0


def test_scan_nonexistent_path_exits_2():
    assert cli.main(["scan", "/definitely/does/not/exist"]) == 2


def test_scan_passes_baseline_commit_through_to_scan_repo(tmp_path, monkeypatch, make_finding):
    _stub_pipeline(monkeypatch, [make_finding(verdict=ValidationVerdict.FALSE_POSITIVE)])
    captured = {}

    def fake_scan_repo(run_id, name, path, baseline_commit=None):
        captured["baseline_commit"] = baseline_commit
        return []

    monkeypatch.setattr(cli, "scan_repo", fake_scan_repo)

    cli.main(["scan", str(tmp_path), "--baseline-commit", "abc123"])

    assert captured["baseline_commit"] == "abc123"


def test_scan_json_output_written_to_file(tmp_path, monkeypatch, make_finding):
    f = make_finding(verdict=ValidationVerdict.CONFIRMED)
    _stub_pipeline(monkeypatch, [f])
    out_file = tmp_path / "report.json"

    cli.main(["scan", str(tmp_path), "--format", "json", "-o", str(out_file)])

    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert len(data["findings"]) == 1
    assert data["findings"][0]["verdict"] == "confirmed"


def test_scan_sarif_output_written_to_file(tmp_path, monkeypatch, make_finding):
    f = make_finding(verdict=ValidationVerdict.CONFIRMED)
    _stub_pipeline(monkeypatch, [f])
    out_file = tmp_path / "report.sarif"

    cli.main(["scan", str(tmp_path), "--format", "sarif", "-o", str(out_file)])

    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
    assert len(data["runs"][0]["results"]) == 1


def test_evaluate_passes_when_thresholds_met(monkeypatch, make_finding):
    entry_findings = [
        make_finding(id="f1", ground_truth_tag="FLASK-SQLI-1", verdict=ValidationVerdict.CONFIRMED)
    ]
    monkeypatch.setattr(cli, "_run_pipeline", lambda targets, validate, prove: entry_findings)

    code = cli.cmd_evaluate(
        cli.build_parser().parse_args(
            [
                "evaluate",
                "--repos",
                "vuln_flask_api",
                "--min-precision",
                "0.0",
                "--min-recall",
                "0.0",
            ]
        )
    )
    assert code == 0


def test_evaluate_fails_when_recall_threshold_not_met(monkeypatch):
    monkeypatch.setattr(cli, "_run_pipeline", lambda targets, validate, prove: [])

    code = cli.cmd_evaluate(
        cli.build_parser().parse_args(
            ["evaluate", "--repos", "vuln_flask_api", "--min-recall", "0.5"]
        )
    )
    assert code == 1
