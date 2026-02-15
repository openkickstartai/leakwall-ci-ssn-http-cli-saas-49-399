#!/usr/bin/env python3
"""LeakWall — Sensitive data leak interceptor for CI/runtime."""
import json
import re
import sys
from pathlib import Path
from typing import Optional

import typer

app = typer.Typer(help="\U0001f9f1 LeakWall — Intercept sensitive data leaks before production")

PATTERNS = [
    ("CREDIT_CARD", r"\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13})\b", "PCI-DSS", "HIGH"),
    ("SSN", r"\b\d{3}-\d{2}-\d{4}\b", "HIPAA", "HIGH"),
    ("AWS_KEY", r"\bAKIA[0-9A-Z]{16}\b", "SECRET", "CRITICAL"),
    ("JWT", r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", "SECRET", "HIGH"),
    ("PRIVATE_KEY", r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", "SECRET", "CRITICAL"),
    ("CONN_STRING", r"(?:postgres|mysql|mongodb|redis)://\S{10,}", "SECRET", "CRITICAL"),
    ("PASSWORD_ASSIGN", r"(?:password|passwd|pwd)\s*[=:]\s*\S{4,}", "PII", "HIGH"),
    ("API_KEY_ASSIGN", r"(?:api[_-]?key|api[_-]?secret|access[_-]?token)\s*[=:]\s*['\"]?\w{20,}", "SECRET", "HIGH"),
]

SCAN_EXTS = {
    ".py", ".js", ".ts", ".go", ".java", ".rb", ".rs", ".sh",
    ".log", ".txt", ".env", ".cfg", ".ini", ".toml",
    ".yml", ".yaml", ".json", ".xml", ".html", ".md",
}


def luhn_check(num: str) -> bool:
    """Validate a number string with the Luhn algorithm."""
    digits = [int(c) for c in num if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d = d * 2 - (9 if d * 2 > 9 else 0)
        total += d
    return total % 10 == 0


def scan_text(text: str, source: str = "<stdin>") -> list:
    """Scan a text string and return a list of findings."""
    findings = []
    for line_num, line in enumerate(text.splitlines(), 1):
        for name, pattern, compliance, severity in PATTERNS:
            for match in re.finditer(pattern, line, re.IGNORECASE):
                value = match.group()
                if name == "CREDIT_CARD" and not luhn_check(value):
                    continue
                masked = value[:4] + "****" + value[-4:] if len(value) > 8 else "****"
                findings.append({
                    "type": name, "severity": severity, "compliance": compliance,
                    "source": source, "line": line_num, "masked_value": masked,
                })
    return findings


def scan_path(path: Path) -> list:
    """Recursively scan a file or directory."""
    if path.is_file():
        try:
            return scan_text(path.read_text(errors="ignore"), str(path))
        except (OSError, PermissionError):
            return []
    findings = []
    for f in sorted(path.rglob("*")):
        if f.is_file() and f.suffix in SCAN_EXTS and ".git" not in f.parts:
            findings.extend(scan_path(f))
    return findings


@app.command()
def scan(
    target: Optional[str] = typer.Argument(None, help="File, directory, or - for stdin"),
    format: str = typer.Option("table", "-f", "--format", help="Output: table, json"),
    fail_on_leak: bool = typer.Option(True, "--fail/--no-fail", help="Exit 1 on leaks (CI mode)"),
):
    """Scan files or stdin for sensitive data leaks."""
    if target is None or target == "-":
        findings = scan_text(sys.stdin.read())
    else:
        p = Path(target)
        if not p.exists():
            typer.echo(f"\u274c Not found: {target}", err=True)
            raise typer.Exit(2)
        findings = scan_path(p)
    if format == "json":
        typer.echo(json.dumps(findings, indent=2))
    elif findings:
        typer.echo(f"\n\U0001f6a8 LeakWall found {len(findings)} leak(s):\n")
        typer.echo(f"  {'Type':<18} {'Sev':<9} {'Compliance':<10} {'Source':<20} {'Line':<5} Value")
        typer.echo("  " + "\u2500" * 78)
        for f in findings:
            typer.echo(
                f"  {f['type']:<18} {f['severity']:<9} {f['compliance']:<10} "
                f"{f['source']:<20} {f['line']:<5} {f['masked_value']}"
            )
        typer.echo(f"\n\U0001f4a1 Fix leaks before merging. Pro: https://leakwall.dev/pricing")
    else:
        typer.echo("\u2705 LeakWall: No sensitive data leaks detected.")
    if findings and fail_on_leak:
        raise typer.Exit(1)


@app.command()
def version():
    """Show version and edition info."""
    typer.echo("\U0001f9f1 LeakWall v0.1.0 (Free Edition)")
    typer.echo("  Pro: custom rules, SARIF, Slack alerts \u2192 https://leakwall.dev/pricing")


if __name__ == "__main__":
    app()
