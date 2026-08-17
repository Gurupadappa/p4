# P4 - Proof-Driven Vulnerability Validation Platform

An automated source-code scanner for interpreted languages that runs a
**Prepare → Scan → Validate → Prove** pipeline and suppresses false positives
via **LLM-assisted validation**, not pattern matching alone. Ships as a
dashboard for interactive triage *and* a `p4` CLI that can gate a CI/CD
pipeline on confirmed findings.

See [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) for the full architecture
and design rationale. This file covers setup and running.

**Docs:** [How P4 works, in plain words](docs/ARCHITECTURE.md)

## What it does

1. **Prepare** - builds a lightweight Code Property Graph (file inventory,
   symbol table, HTTP entrypoint map) for a repo without requiring a build.
2. **Scan** - runs Semgrep with our own pattern rules (`backend/rules/`,
   tuned for injection, insecure deserialization, and SSRF) plus Semgrep's
   public registry rulesets (`p/security-audit`, `p/secrets`,
   `p/owasp-top-ten`) for broad coverage - XSS, path traversal, hardcoded
   secrets, crypto misuse, and more. This intentionally behaves like a naive
   baseline SAST tool - it casts a wide net and produces false positives on
   purpose, which is what Validate exists to fix.
3. **Validate** - an LLM agent (Google Gemini) reads each candidate finding in
   context and decides whether it's really exploitable, clearing false
   positives a pattern-matcher can't. It also assigns a canonical vulnerability
   signature used to **dedupe the same vulnerability class across repos**.
4. **Prove** - for every confirmed finding, the LLM writes a concrete
   proof-of-concept narrative. For P4's own sample repos, this is backed by
   real evidence, not just LLM text: `backend/core/verify.py` builds and
   runs an isolated, throwaway container of the actual target app and
   exploits the finding for real (an out-of-band callback for SSRF/command
   injection/deserialization RCE, a differential response check for SQL
   injection) - `finding.verified` reflects whether it actually reproduced,
   not whether the model said it would.

Cross-cutting: a **human-approval gate** (a fix patch is only generated after
a reviewer clicks Approve), **SLA-breach badges** on confirmed findings older
than 72h, and a **DefectDojo export adapter** for remediation tickets.

## Setup

```bash
pip install -e ".[dev]"
```

Get a free Gemini API key at [aistudio.google.com/apikey](https://aistudio.google.com/apikey)
(no card required) and put it in a `.env` file at the project root:

```
GEMINI_API_KEY=your-key-here
```

## Run the dashboard

```bash
python -m uvicorn backend.api.main:app --port 8000
```

Open `http://localhost:8000`, select which sample repos to scan, and click
**Run Scan**. A full run against all three sample repos takes ~2 minutes
(Gemini's free tier is rate-limited; the client retries automatically).

## Run as a CI/CD security gate - the `p4` CLI

`pip install -e .` also installs a `p4` command that runs the same pipeline
headlessly against a repo path and exits non-zero if it finds a confirmed
vulnerability - no dashboard, no clicking, just an exit code and a report:

```bash
# Scan the current checked-out repo; fails the build on any confirmed finding.
p4 scan .

# Only fail on high/critical, and emit a SARIF report GitHub can render
# inline on the PR's Security tab.
p4 scan . --min-severity high --format sarif -o results.sarif

# Sanity-check the wiring without an API key (Prepare + Scan only - cannot
# gate on confirmed findings in this mode).
p4 scan . --skip-validate

# Diff-aware: only gate on findings introduced since the PR's base commit,
# so adopting P4 in a repo with pre-existing findings doesn't fail every PR.
p4 scan . --baseline-commit "$(git merge-base origin/main HEAD)"

# Score the pipeline against the labeled ground truth in sample_repos/ and
# fail if precision/recall regresses - used by this repo's own CI as a
# "dogfooding" check (see .github/workflows/ci.yml).
p4 evaluate --min-precision 0.85 --min-recall 1.0
```

Run `p4 scan --help` / `p4 evaluate --help` for the full flag list. A
reusable GitHub Action wrapping the CLI lives at [`action.yml`](action.yml)
so other repositories can drop P4 into their own workflows:

```yaml
permissions:
  contents: read
  security-events: write # required for the SARIF upload step

steps:
  - uses: actions/checkout@v4
    with:
      fetch-depth: 0 # needed so the baseline commit below is reachable
  - uses: <org>/p4@main
    with:
      path: .
      gemini-api-key: ${{ secrets.GEMINI_API_KEY }}
      fail-on: confirmed
      min-severity: high
```

The action uploads results as SARIF via `github/codeql-action/upload-sarif`,
so confirmed findings show up inline on the PR's Security tab, not just in
the build log. On `pull_request` events it automatically diffs against the
PR's base commit (`github.event.pull_request.base.sha`) - only newly
introduced findings gate the build, so dropping P4 into a repo with existing,
untriaged findings doesn't fail every open PR on day one. Pass
`baseline-commit: ""` explicitly to force a full-repo scan instead, or a
specific commit to override the default.

## Run with Docker

```bash
docker build -t p4 .
docker run --rm -p 8000:8000 --env-file .env p4
```

or, for local development:

```bash
docker compose up --build
```

## Evaluating against a baseline (Model Performance)

`sample_repos/` contains three intentionally-vulnerable apps (2 Flask, 1
Express) with a hand-labeled ground truth (`sample_repos/ANSWER_KEY.json`):
9 real vulnerabilities, 4 planted false-positive traps designed to fool a
pattern-only scanner, and one vulnerability pattern (SSRF) deliberately
duplicated across all three repos to exercise cross-repo dedup.

The dashboard's comparison panel - and `p4 evaluate` on the command line -
compute precision/recall/F1 for the raw Semgrep baseline vs. P4 post-Validate
directly from this answer key - typical runs show baseline precision around
**69%** (4 false positives) vs. P4 at **90–100%** (1–0 false positives), a
false-positive suppression rate of 75–100%, with recall staying at 100% both
ways.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check backend tests
ruff format backend tests
```

CI (`.github/workflows/ci.yml`) runs the same lint/test steps on every push,
builds the frontend and the Docker image, and - when `GEMINI_API_KEY` is
available as a repo secret - runs `p4 evaluate` as a regression gate on the
pipeline's own precision/recall.

## Project layout

```
backend/
  cli.py                            # `p4` CLI - CI/CD security gate
  core/
    prepare.py       # Stage 1
    scan.py           # Stage 2 (Semgrep)
    validate.py        # Stage 3 (Gemini)
    prove.py             # Stage 4 (Gemini) + on-approval fix generation
    dedupe.py              # cross-repo grouping
    evaluation.py             # precision/recall/F1 vs. ground truth
    sarif.py                    # SARIF 2.1.0 output for code-scanning UIs
    severity.py                   # Semgrep -> low/medium/high/critical scale
    defectdojo.py                   # remediation ticket export
    pipeline.py                       # web-dashboard orchestrator + SLA/approval
    store.py                            # SQLite persistence
    llm.py                                # Gemini client
  api/main.py                               # FastAPI endpoints
backend/rules/                                # Semgrep rules (injection/deserialization/ssrf)
frontend/                                       # React + Vite dashboard
sample_repos/                                     # demo targets + ANSWER_KEY.json
tests/                                              # pytest suite
action.yml                                            # reusable GitHub Action
```

## Notes

- Uses Google Gemini (`gemini-flash-lite-latest` by default - override with
  `GEMINI_MODEL`) rather than a paid API, so the whole thing runs on a free
  tier. Swapping providers only touches `backend/core/llm.py`.
- The DefectDojo sync works against a real instance if `DEFECTDOJO_URL` /
  `DEFECTDOJO_API_KEY` are set; otherwise it writes the same payload to
  `run_artifacts/` so the integration is demonstrable without a live instance.
- This project was originally prototyped under the name "Quadrant"; it's now
  P4. The Python package layout (`backend.core.*`) is unchanged - only the
  product name, CLI, and docs use P4.
