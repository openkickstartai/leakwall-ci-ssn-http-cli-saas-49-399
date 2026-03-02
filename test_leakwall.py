"""Tests for LeakWall sensitive data leak detection engine."""
import os
import tempfile
from pathlib import Path

from leakwall import (
    load_config,
    luhn_check,
    scan_text,
    is_allowlisted,
    passes_severity_threshold,
    get_all_patterns,
    PATTERNS,
    DEFAULT_CONFIG,
)

FIXTURE_DIR = Path(__file__).parent / "tests" / "fixtures"


# ─── Original built-in detector tests ────────────────────────────────────────

def test_credit_card_visa_detected():
    findings = scan_text("Payment logged: 4111111111111111 done")
    cc = [f for f in findings if f["type"] == "CREDIT_CARD"]
    assert len(cc) == 1
    assert cc[0]["compliance"] == "PCI-DSS"
    assert cc[0]["severity"] == "HIGH"
    assert "****" in cc[0]["masked_value"]


def test_credit_card_mastercard_detected():
    findings = scan_text("Card: 5500000000000004")
    cc = [f for f in findings if f["type"] == "CREDIT_CARD"]
    assert len(cc) == 1


def test_credit_card_invalid_luhn_skipped():
    findings = scan_text("Not a card: 4111111111111112")
    cc = [f for f in findings if f["type"] == "CREDIT_CARD"]
    assert len(cc) == 0


def test_ssn_detected():
    findings = scan_text("Patient SSN: 123-45-6789")
    ssn = [f for f in findings if f["type"] == "SSN"]
    assert len(ssn) == 1
    assert ssn[0]["compliance"] == "HIPAA"
    assert ssn[0]["line"] == 1


def test_aws_key_detected():
    findings = scan_text("export AWS_KEY=AKIAIOSFODNN7EXAMPLE")
    aws = [f for f in findings if f["type"] == "AWS_KEY"]
    assert len(aws) == 1
    assert aws[0]["severity"] == "CRITICAL"


def test_jwt_detected():
    token = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    )
    findings = scan_text(f"Authorization: Bearer {token}")
    jwt_f = [f for f in findings if f["type"] == "JWT"]
    assert len(jwt_f) == 1


def test_connection_string_detected():
    findings = scan_text("DATABASE_URL=postgres://admin:s3cret@db.prod.com:5432/main")
    cs = [f for f in findings if f["type"] == "CONN_STRING"]
    assert len(cs) == 1
    assert cs[0]["severity"] == "CRITICAL"


def test_private_key_detected():
    findings = scan_text("-----BEGIN RSA PRIVATE KEY-----")
    pk = [f for f in findings if f["type"] == "PRIVATE_KEY"]
    assert len(pk) == 1
    assert pk[0]["severity"] == "CRITICAL"


def test_password_detected():
    findings = scan_text("password=S3cret!123")
    pw = [f for f in findings if f["type"] == "PASSWORD_ASSIGN"]
    assert len(pw) == 1
    assert pw[0]["compliance"] == "PII"


def test_api_key_detected():
    findings = scan_text("api_key=abcdefghij1234567890extra")
    ak = [f for f in findings if f["type"] == "API_KEY_ASSIGN"]
    assert len(ak) == 1


def test_luhn_valid():
    assert luhn_check("4111111111111111") is True


def test_luhn_invalid():
    assert luhn_check("4111111111111112") is False


def test_clean_text_no_findings():
    findings = scan_text("Hello world, nothing sensitive here.")
    assert len(findings) == 0


# ─── Config loading tests ────────────────────────────────────────────────────

def test_load_config_default_when_no_file():
    """When config file does not exist, return defaults without error."""
    config = load_config("/nonexistent/path/.leakwall.yml")
    assert config["allowlist"] == []
    assert config["custom_patterns"] == []
    assert config["severity_threshold"] == "LOW"


def test_load_config_from_yaml_file():
    """Load and parse the fixture .leakwall.yml correctly."""
    config_path = FIXTURE_DIR / ".leakwall.yml"
    config = load_config(str(config_path))
    assert config["severity_threshold"] == "HIGH"
    assert len(config["allowlist"]) >= 1
    assert len(config["custom_patterns"]) >= 1
    # Verify custom pattern structure
    emp_patterns = [p for p in config["custom_patterns"] if p["id"] == "EMPLOYEE_ID"]
    assert len(emp_patterns) == 1
    assert emp_patterns[0]["severity"] == "medium"


def test_load_config_malformed_yaml_returns_defaults():
    """Malformed YAML should return defaults, not crash."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
        f.write(": : : [invalid yaml\n")
        f.flush()
        try:
            config = load_config(f.name)
            assert config["allowlist"] == []
            assert config["severity_threshold"] == "LOW"
        finally:
            os.unlink(f.name)


# ─── Custom pattern tests ────────────────────────────────────────────────────

def test_custom_pattern_detected():
    """Custom pattern for employee IDs should match."""
    config = {
        "allowlist": [],
        "custom_patterns": [
            {
                "id": "EMPLOYEE_ID",
                "description": "Internal employee ID",
                "regex": r"EMP-\d{6}",
                "severity": "MEDIUM",
                "compliance": "INTERNAL",
            }
        ],
        "severity_threshold": "LOW",
    }
    findings = scan_text("Assigned to EMP-123456 for review", config=config)
    emp = [f for f in findings if f["type"] == "EMPLOYEE_ID"]
    assert len(emp) == 1
    assert emp[0]["compliance"] == "INTERNAL"
    assert emp[0]["severity"] == "MEDIUM"
    assert emp[0]["line"] == 1


def test_custom_pattern_no_false_positive():
    """Custom pattern should not match unrelated text."""
    config = {
        "allowlist": [],
        "custom_patterns": [
            {
                "id": "EMPLOYEE_ID",
                "description": "Internal employee ID",
                "regex": r"EMP-\d{6}",
                "severity": "MEDIUM",
            }
        ],
        "severity_threshold": "LOW",
    }
    findings = scan_text("No employee data here, just EMP notes", config=config)
    emp = [f for f in findings if f["type"] == "EMPLOYEE_ID"]
    assert len(emp) == 0


# ─── Allowlist tests ─────────────────────────────────────────────────────────

def test_allowlist_regex_excludes_finding():
    """Allowlist with regex should exclude matching findings."""
    config = {
        "allowlist": [
            {"regex": "4111111111111111"},  # Test card number
        ],
        "custom_patterns": [],
        "severity_threshold": "LOW",
    }
    findings = scan_text("Card: 4111111111111111", config=config)
    cc = [f for f in findings if f["type"] == "CREDIT_CARD"]
    assert len(cc) == 0, "Allowlisted card number should be excluded"


def test_allowlist_file_glob_excludes_finding():
    """Allowlist with file glob should exclude findings from matched files."""
    config = {
        "allowlist": [
            {"file": "tests/fixtures/*"},
        ],
        "custom_patterns": [],
        "severity_threshold": "LOW",
    }
    # Findings from a file matching the glob should be excluded
    findings = scan_text(
        "Patient SSN: 123-45-6789",
        source="tests/fixtures/sample.log",
        config=config,
    )
    assert len(findings) == 0, "Findings from allowlisted file glob should be excluded"

    # Findings from a non-matching file should NOT be excluded
    findings2 = scan_text(
        "Patient SSN: 123-45-6789",
        source="src/app.py",
        config=config,
    )
    ssn = [f for f in findings2 if f["type"] == "SSN"]
    assert len(ssn) == 1, "Non-allowlisted source should still report findings"


def test_allowlist_no_effect_on_nonmatching():
    """Allowlist rule should not suppress findings that don't match."""
    config = {
        "allowlist": [
            {"regex": "NEVER_MATCHES_ANYTHING_12345"},
        ],
        "custom_patterns": [],
        "severity_threshold": "LOW",
    }
    findings = scan_text("AWS key: AKIAIOSFODNN7EXAMPLE", config=config)
    aws = [f for f in findings if f["type"] == "AWS_KEY"]
    assert len(aws) == 1, "Non-matching allowlist should not affect findings"


# ─── Severity threshold tests ────────────────────────────────────────────────

def test_severity_threshold_filters_below():
    """Findings below severity threshold should be filtered out."""
    config = {
        "allowlist": [],
        "custom_patterns": [
            {
                "id": "LOW_ITEM",
                "description": "Low severity test",
                "regex": r"LOW_MARKER_\w+",
                "severity": "LOW",
            }
        ],
        "severity_threshold": "HIGH",
    }
    # LOW severity custom pattern should be filtered when threshold is HIGH
    findings = scan_text("Found LOW_MARKER_abc123 in logs", config=config)
    low = [f for f in findings if f["type"] == "LOW_ITEM"]
    assert len(low) == 0, "LOW severity should be filtered when threshold is HIGH"


def test_severity_threshold_passes_at_or_above():
    """Findings at or above severity threshold should pass through."""
    config = {
        "allowlist": [],
        "custom_patterns": [],
        "severity_threshold": "HIGH",
    }
    # SSN is HIGH severity — should pass HIGH threshold
    findings = scan_text("SSN: 123-45-6789", config=config)
    ssn = [f for f in findings if f["type"] == "SSN"]
    assert len(ssn) == 1, "HIGH severity should pass HIGH threshold"

    # AWS_KEY is CRITICAL — should pass HIGH threshold
    findings2 = scan_text("key=AKIAIOSFODNN7EXAMPLE", config=config)
    aws = [f for f in findings2 if f["type"] == "AWS_KEY"]
    assert len(aws) == 1, "CRITICAL severity should pass HIGH threshold"


def test_severity_threshold_critical_only():
    """When threshold is CRITICAL, only CRITICAL findings should appear."""
    config = {
        "allowlist": [],
        "custom_patterns": [],
        "severity_threshold": "CRITICAL",
    }
    text = "\n".join([
        "Card: 4111111111111111",           # HIGH
        "SSN: 123-45-6789",                 # HIGH
        "key=AKIAIOSFODNN7EXAMPLE",          # CRITICAL
        "-----BEGIN RSA PRIVATE KEY-----",   # CRITICAL
    ])
    findings = scan_text(text, config=config)
    # Only CRITICAL findings should survive
    for f in findings:
        assert f["severity"] == "CRITICAL", f"Expected CRITICAL, got {f['severity']} for {f['type']}"
    types = {f["type"] for f in findings}
    assert "AWS_KEY" in types
    assert "PRIVATE_KEY" in types
    assert "CREDIT_CARD" not in types
    assert "SSN" not in types


def test_passes_severity_threshold_function():
    """Unit test for the passes_severity_threshold helper."""
    assert passes_severity_threshold("CRITICAL", "LOW") is True
    assert passes_severity_threshold("HIGH", "LOW") is True
    assert passes_severity_threshold("MEDIUM", "HIGH") is False
    assert passes_severity_threshold("LOW", "CRITICAL") is False
    assert passes_severity_threshold("HIGH", "HIGH") is True
    assert passes_severity_threshold("CRITICAL", "CRITICAL") is True
