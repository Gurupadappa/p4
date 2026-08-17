"""Evaluation harness for the demo repos: computes precision/recall/F1 for
the raw Semgrep baseline vs. the full pipeline (post-Validate), using the
planted ground truth in sample_repos/ANSWER_KEY.json. This is what backs the
"false-positive suppression rate vs a baseline SAST tool" comparison.
"""

from __future__ import annotations

import json
from pathlib import Path

from .models import Finding, ValidationVerdict

ANSWER_KEY_PATH = Path(__file__).resolve().parent.parent.parent / "sample_repos" / "ANSWER_KEY.json"


def _load_answer_key() -> dict[str, dict]:
    data = json.loads(ANSWER_KEY_PATH.read_text(encoding="utf-8"))
    return {entry["tag"]: entry for entry in data["findings"]}


def _prf1(tp: int, fp: int, fn: int) -> dict:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
    }


def compute_report(findings: list[Finding]) -> dict:
    answer_key = _load_answer_key()
    total_true_vulns = sum(1 for e in answer_key.values() if e["ground_truth"] == "true_positive")

    # Group by planted tag first: with a broad ruleset, several rules can
    # independently flag the same planted line, and we want to score "did we
    # catch this vulnerability" (one vote per tag), not "how many rules fired".
    findings_by_tag: dict[str, list[Finding]] = {}
    for f in findings:
        if f.ground_truth_tag and f.ground_truth_tag in answer_key:
            findings_by_tag.setdefault(f.ground_truth_tag, []).append(f)

    matched_tags = set(findings_by_tag)
    baseline_tp = baseline_fp = 0
    pipeline_tp = pipeline_fp = 0

    for tag, tag_findings in findings_by_tag.items():
        is_true_vuln = answer_key[tag]["ground_truth"] == "true_positive"

        # Baseline: the raw scan flagged this line at all (what a
        # pattern-matching-only tool would report).
        if is_true_vuln:
            baseline_tp += 1
        else:
            baseline_fp += 1

        # Pipeline: at least one of the findings on this line survived Validate.
        if any(f.verdict == ValidationVerdict.CONFIRMED for f in tag_findings):
            if is_true_vuln:
                pipeline_tp += 1
            else:
                pipeline_fp += 1

    baseline_fn = total_true_vulns - baseline_tp
    pipeline_fn = total_true_vulns - pipeline_tp

    baseline = _prf1(baseline_tp, baseline_fp, baseline_fn)
    pipeline = _prf1(pipeline_tp, pipeline_fp, pipeline_fn)

    fp_suppression = None
    if baseline["false_positives"] > 0:
        fp_suppression = round(
            (baseline["false_positives"] - pipeline["false_positives"])
            / baseline["false_positives"],
            3,
        )

    dedup_groups = {f.dedup_group_id for f in findings if f.dedup_group_id}

    return {
        "total_true_vulns_planted": total_true_vulns,
        "answer_key_coverage": f"{len(matched_tags)}/{len(answer_key)}",
        "baseline": baseline,
        "pipeline": pipeline,
        "false_positive_suppression_rate": fp_suppression,
        "cross_repo_dedup_groups": len(dedup_groups),
    }
