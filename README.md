# 🧱 LeakWall

**Intercept sensitive data leaks before production.** Scan logs, configs, test output, and source code for credit cards, SSNs, API keys, JWTs, passwords, and connection strings — in CI or locally.

> One leaked credit card in a log file = PCI-DSS audit failure = $$$. LeakWall catches it in your PR.

## 🚀 Quick Start

```bash
pip install -r requirements.txt

# Scan a file
python leakwall.py scan app.log

# Scan a directory
python leakwall.py scan ./src

# Pipe from stdin
cat server.log | python leakwall.py scan -

# JSON output for CI tooling
python leakwall.py scan . --format json

# Don't fail (just report)
python leakwall.py scan . --no-fail
```

## 🔍 What It Detects

| Type | Example | Compliance |
|------|---------|------------|
| Credit Cards | `4111111111111111` (Luhn-validated) | PCI-DSS |
| SSNs | `123-45-6789` | HIPAA |
| AWS Keys | `AKIAIOSFODNN7EXAMPLE` | SECRET |
| JWTs | `eyJhbGciOi...` | SECRET |
| Private Keys | `-----BEGIN RSA PRIVATE KEY-----` | SECRET |
| Connection Strings | `postgres://user:pass@host/db` | SECRET |
| Passwords | `password=S3cret!` | PII |
| API Keys | `api_key=abc123...` | SECRET |

## 🔌 GitHub Actions

```yaml
- name: LeakWall Scan
  run: |
    pip install typer
    python leakwall.py scan ./src
```

Exit code `1` = leaks found → PR blocked. Zero config.

## 📊 Why Pay for LeakWall?

A single PCI-DSS audit failure costs **$5,000–$500,000**. A HIPAA breach averages **$1.3M**. LeakWall costs less than your team's coffee budget.

## 💰 Pricing

| Feature | Free | Pro ($49/mo) | Enterprise ($399/mo) |
|---------|------|-------------|---------------------|
| 8 built-in detectors | ✅ | ✅ | ✅ |
| CLI scanning | ✅ | ✅ | ✅ |
| JSON output | ✅ | ✅ | ✅ |
| GitHub Action | ✅ | ✅ | ✅ |
| Custom regex rules | ❌ | ✅ | ✅ |
| SARIF output (GitHub Security tab) | ❌ | ✅ | ✅ |
| Slack/Teams alerts | ❌ | ✅ | ✅ |
| Baseline/ignore file | ❌ | ✅ | ✅ |
| PDF compliance report | ❌ | ❌ | ✅ |
| ASGI/WSGI middleware | ❌ | ❌ | ✅ |
| Runtime log interception | ❌ | ❌ | ✅ |
| SSO + audit log | ❌ | ❌ | ✅ |
| SLA + dedicated support | ❌ | ❌ | ✅ |

## 📄 License

Free edition: MIT. Pro/Enterprise: commercial license at [leakwall.dev](https://leakwall.dev).
