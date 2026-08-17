"""P4 CLI — Proof-Driven Vulnerability Validation Platform.

Runs the Prepare -> Scan -> Validate -> (optional Prove) pipeline against a
local repo path and reports a pass/fail verdict, so it can be dropped into a
CI/CD pipeline as a security gate. Reuses the same stage functions as the
web dashboard (backend.core.*) rather than going through the HTTP API.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core.dedupe import dedupe_findings
from .core.evaluation import compute_report
from .core.models import Finding, ValidationVerdict, new_id
from .core.prepare import prepare_repo
from .core.prove import prove_findings
from .core.sarif import build_sarif
from .core.scan import scan_repo
from .core.severity import meets_minimum
from .core.validate import validate_findings
from .core.verify import verify_findings

NAME = "p4"
VERSION = "0.1.0"
TAGLINE = "P4 - Proof-Driven Vulnerability Validation Platform"

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_REPOS_DIR = REPO_ROOT / "sample_repos"


def _run_pipeline(
    targets: dict[str, str], *, validate: bool, prove: bool, baseline_commit: str | None = None
) -> list[Finding]:
    run_id = new_id("cli")
    findings: list[Finding] = []
    cpg_by_repo = {}
    for name, path in targets.items():
        cpg_by_repo[name] = prepare_repo(name, path)
        findings.extend(scan_repo(run_id, name, path, baseline_commit))

    if validate and findings:
        validate_findings(findings, cpg_by_repo)
        dedupe_findings(findings)

    if prove and findings:
        prove_findings(findings)
        verify_findings(findings)

    return findings


def _print_table(findings: list[Finding]) -> None:
    confirmed = [f for f in findings if f.verdict == ValidationVerdict.CONFIRMED]
    if not confirmed:
        print("No confirmed findings.")
        return
    width = max(len(f"{f.repo}/{f.file}:{f.line}") for f in confirmed)
    print(f"{'LOCATION'.ljust(width)}  SEVERITY  VULN CLASS            RULE")
    for f in confirmed:
        loc = f"{f.repo}/{f.file}:{f.line}"
        print(f"{loc.ljust(width)}  {f.severity:<8}  {f.vuln_class:<20}  {f.rule_id}")
    print(f"\n{len(confirmed)} confirmed finding(s) out of {len(findings)} candidate(s).")


def _emit(payload: str, output: str | None, kind: str) -> None:
    if output:
        Path(output).write_text(payload, encoding="utf-8")
        print(f"wrote {kind} report to {output}", file=sys.stderr)
    else:
        print(payload)


def cmd_scan(args: argparse.Namespace) -> int:
    target_path = Path(args.path).resolve()
    if not target_path.is_dir():
        print(f"error: not a directory: {target_path}", file=sys.stderr)
        return 2
    repo_name = args.name or target_path.name

    print(f"{TAGLINE}\nscanning '{repo_name}' at {target_path} ...", file=sys.stderr)
    try:
        findings = _run_pipeline(
            {repo_name: str(target_path)},
            validate=not args.skip_validate,
            prove=args.prove,
            baseline_commit=args.baseline_commit,
        )
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    visible = [f for f in findings if meets_minimum(f.severity, args.min_severity)]

    if args.format == "table":
        _print_table(visible)
    elif args.format == "json":
        _emit(
            json.dumps({"findings": [f.to_dict() for f in visible]}, indent=2), args.output, "json"
        )
    elif args.format == "sarif":
        _emit(json.dumps(build_sarif(visible), indent=2), args.output, "sarif")

    if args.skip_validate:
        print("\ngate: skipped (--skip-validate - no verdicts to gate on)", file=sys.stderr)
        return 0
    if args.fail_on == "none":
        print("\ngate: not enforced (--fail-on none)", file=sys.stderr)
        return 0

    confirmed = [f for f in visible if f.verdict == ValidationVerdict.CONFIRMED]
    if confirmed:
        print(
            f"\ngate: FAIL - {len(confirmed)} confirmed finding(s) at/above severity '{args.min_severity}'",
            file=sys.stderr,
        )
        return 1
    print(
        f"\ngate: PASS - no confirmed findings at/above severity '{args.min_severity}'",
        file=sys.stderr,
    )
    return 0


def cmd_evaluate(args: argparse.Namespace) -> int:
    if not SAMPLE_REPOS_DIR.exists():
        print(f"error: sample_repos not found at {SAMPLE_REPOS_DIR}", file=sys.stderr)
        return 2

    names = args.repos or sorted(
        p.name for p in SAMPLE_REPOS_DIR.iterdir() if p.is_dir() and not p.name.startswith(".")
    )
    targets = {name: str(SAMPLE_REPOS_DIR / name) for name in names}

    print(f"{TAGLINE}\nevaluating against ground truth: {', '.join(names)}", file=sys.stderr)
    try:
        findings = _run_pipeline(targets, validate=True, prove=False)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report = compute_report(findings)
    print(json.dumps(report, indent=2))

    failures = []
    if args.min_precision is not None and report["pipeline"]["precision"] < args.min_precision:
        failures.append(f"precision {report['pipeline']['precision']} < {args.min_precision}")
    if args.min_recall is not None and report["pipeline"]["recall"] < args.min_recall:
        failures.append(f"recall {report['pipeline']['recall']} < {args.min_recall}")

    if failures:
        print("\nevaluate: FAIL - " + "; ".join(failures), file=sys.stderr)
        return 1
    print("\nevaluate: PASS", file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=NAME, description=TAGLINE)
    parser.add_argument("--version", action="version", version=f"{NAME} {VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a repo and gate on confirmed findings (for CI/CD).")
    scan.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to the repo to scan (default: current directory).",
    )
    scan.add_argument(
        "--name", help="Repo name to use in findings/reports (default: directory name)."
    )
    scan.add_argument(
        "--skip-validate",
        action="store_true",
        help="Run Prepare+Scan only (no LLM calls, no API key required). Cannot gate on confirmed findings in this mode.",
    )
    scan.add_argument(
        "--prove",
        action="store_true",
        help="Also generate proof-of-concepts for confirmed findings (extra LLM calls) and, "
        "for P4's own sample repos, attempt real sandboxed exploitation to verify them "
        "(requires Docker; degrades gracefully to unverified without it).",
    )
    scan.add_argument(
        "--baseline-commit",
        default=None,
        help="Only report findings not already present at this commit (diff-aware "
        "scanning). Requires path to be a clean git working directory with this "
        "commit reachable locally, e.g. --baseline-commit \"$(git merge-base origin/main HEAD)\" "
        "in a PR job. Without it, every pre-existing finding in the repo is reported "
        "on every run — fine for a fresh repo, not for adopting P4 into a legacy one.",
    )
    scan.add_argument(
        "--min-severity",
        choices=["low", "medium", "high", "critical"],
        default="low",
        help="Only report/gate on findings at or above this severity (default: low).",
    )
    scan.add_argument(
        "--fail-on",
        choices=["confirmed", "none"],
        default="confirmed",
        help="'confirmed' (default) fails the build on any confirmed finding; 'none' always exits 0 (report-only).",
    )
    scan.add_argument(
        "--format", choices=["table", "json", "sarif"], default="table", help="Output format."
    )
    scan.add_argument(
        "-o", "--output", help="Write the json/sarif report to this file instead of stdout."
    )
    scan.set_defaults(func=cmd_scan)

    evaluate = sub.add_parser(
        "evaluate",
        help="Run the pipeline against sample_repos/ and score it against the labeled ground truth.",
    )
    evaluate.add_argument(
        "--repos",
        nargs="*",
        help="Sample repo names to include (default: all under sample_repos/).",
    )
    evaluate.add_argument(
        "--min-precision",
        type=float,
        default=None,
        help="Fail if pipeline precision drops below this.",
    )
    evaluate.add_argument(
        "--min-recall", type=float, default=None, help="Fail if pipeline recall drops below this."
    )
    evaluate.set_defaults(func=cmd_evaluate)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
