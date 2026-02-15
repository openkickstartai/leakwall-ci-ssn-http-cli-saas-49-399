# 🔌 LeakWall Integration Guide

LeakWall can be integrated into your development workflow in minutes. This guide covers three common setups: **pre-commit hooks**, **GitHub Actions**, and **GitLab CI**.

---

## 1. Pre-commit Hook

[pre-commit](https://pre-commit.com/) runs LeakWall automatically on every `git commit`, scanning only the staged files. Leaked secrets never reach your remote repository.

### Setup

Add to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/your-org/leakwall
    rev: v0.1.0  # pin to a release tag
    hooks:
      - id: leakwall
```

Then install the hook:

```bash
pip install pre-commit
pre-commit install
```

### How it works

- Only **staged files** (text type) are scanned — binary files are skipped automatically.
- If any sensitive data is detected, the commit is **blocked** and findings are printed.
- The hook runs `leakwall scan` under the hood with each staged file as an argument.

### Verify locally

You can test the hook against this repository without installing it globally:

```bash
pre-commit try-repo . leakwall --files README.md
```

### Customization

Override default arguments in `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/your-org/leakwall
    rev: v0.1.0
    hooks:
      - id: leakwall
        args: ['--format', 'json', '--no-fail']
        # Limit to specific file types:
        types_or: [python, javascript, yaml]
```

---

## 2. GitHub Actions

LeakWall ships a **Composite Action** (`action.yml`) that you can reference directly in any workflow.

### Minimal workflow

```yaml
# .github/workflows/leakwall.yml
name: LeakWall

on:
  push:
    branches: [main]
  pull_request:

jobs:
  leak-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Scan for sensitive data
        uses: your-org/leakwall@main
        with:
          severity: HIGH
          format: text
          path: '.'
```

If leaks are found the step exits with code `1`, which **blocks the PR** from merging (when branch protection is enabled).

### Full workflow with SARIF upload

Upload results to GitHub's **Security → Code scanning** tab:

```yaml
name: LeakWall Security Scan

on:
  push:
    branches: [main]
  pull_request:

permissions:
  security-events: write
  contents: read

jobs:
  leak-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: LeakWall SARIF scan
        uses: your-org/leakwall@main
        with:
          severity: HIGH
          format: sarif
          path: './src'
          fail-on-leak: 'true'
```

The action automatically uploads `leakwall-results.sarif` to GitHub Security when `format` is `sarif`.

### Action inputs reference

| Input | Default | Description |
|-------|---------|-------------|
| `severity` | `HIGH` | Minimum severity: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `format` | `text` | Output format: `text`, `json`, `sarif` |
| `config` | _(empty)_ | Path to custom config file |
| `path` | `.` | File or directory to scan |
| `fail-on-leak` | `true` | Set `false` to report without failing |
| `python-version` | `3.11` | Python version for the runner |

---

## 3. GitLab CI

Add a LeakWall scanning stage to your `.gitlab-ci.yml`:

### Basic setup

```yaml
stages:
  - test
  - security

leakwall-scan:
  stage: security
  image: python:3.11-slim
  before_script:
    - pip install typer
  script:
    - python leakwall.py scan . --format text
  allow_failure: false
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '$CI_COMMIT_BRANCH == "main"'
```

### With JSON artifact

Save scan results as a downloadable CI artifact:

```yaml
leakwall-scan:
  stage: security
  image: python:3.11-slim
  before_script:
    - pip install typer
  script:
    - python leakwall.py scan . --format json > leakwall-report.json
  artifacts:
    paths:
      - leakwall-report.json
    when: always
    expire_in: 30 days
  allow_failure: false
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '$CI_COMMIT_BRANCH == "main"'
```

### Scanning only changed files in MRs

For faster scans on merge requests, scan only the files changed in the MR:

```yaml
leakwall-scan-mr:
  stage: security
  image: python:3.11-slim
  before_script:
    - pip install typer
  script:
    - |
      CHANGED_FILES=$(git diff --name-only --diff-filter=ACMR origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME)
      if [ -n "$CHANGED_FILES" ]; then
        echo "$CHANGED_FILES" | xargs python leakwall.py scan
      else
        echo "No changed files to scan."
      fi
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
```

---

## Troubleshooting

### False positives

If LeakWall flags test fixtures or example data, use `--no-fail` during initial rollout to audit findings before enforcing blocks:

```bash
# Pre-commit
hooks:
  - id: leakwall
    args: ['--no-fail']

# GitHub Actions
with:
  fail-on-leak: 'false'

# GitLab CI
script:
  - python leakwall.py scan . --no-fail
```

### Performance

LeakWall only scans files with known text extensions (`.py`, `.js`, `.log`, `.env`, `.yaml`, etc.). Binary files and common non-text formats are skipped automatically.

---

## Next Steps

- **Free tier**: 8 built-in detectors, CLI, JSON output, CI integration
- **Pro ($49/mo)**: Custom regex rules, SARIF output, team dashboards
- **Enterprise ($399/mo)**: SSO, audit trail, SLA support, unlimited repos

Visit [leakwall.dev](https://leakwall.dev) to get started.
