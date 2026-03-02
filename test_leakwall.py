"""Tests for LeakWall sensitive data leak detection engine."""
import json

from leakwall import (
    format_json,
    format_sarif,
    format_text,
    luhn_check,
    scan_text,
)


# --- Detection tests ---


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


def test_password_detected():
    findings = scan_text("password=SuperS3cret!")
    pw = [f for f in findings if f["type"] == "PASSWORD_ASSIGN"]
    assert len(pw) == 1
    assert pw[0]["compliance"] == "PII"


def test_api_key_detected():
    findings = scan_text("api_key=abcdefghijklmnopqrstuvwxyz")
    ak = [f for f in findings if f["type"] == "API_KEY_ASSIGN"]
    assert len(ak) == 1


def test_private_key_detected():
    findings = scan_text("-----BEGIN RSA PRIVATE KEY-----")
    pk = [f for f in findings if f["type"] == "PRIVATE_KEY"]
    assert len(pk) == 1
    assert pk[0]["severity"] == "CRITICAL"


def test_no_leaks_clean_text():
    findings = scan_text("This is a perfectly clean log line.")
    assert len(findings) == 0


# --- Luhn tests ---


def test_luhn_valid():
    assert luhn_check("4111111111111111") is True


def test_luhn_invalid():
    assert luhn_check("4111111111111112") is False


def test_luhn_too_short():
    assert luhn_check("123") is False


# --- Position tracking tests ---


def test_column_tracking():
    findings = scan_text("prefix 123-45-6789 suffix")
    ssn = [f for f in findings if f["type"] == "SSN"]
    assert len(ssn) == 1
    assert ssn[0]["column"] == 8


def test_multiline_scan():
    text = "line one\npassword=MyS3cret!\nline three"
    findings = scan_text(text)
    pw = [f for f in findings if f["type"] == "PASSWORD_ASSIGN"]
    assert len(pw) == 1
    assert pw[0]["line"] == 2


def test_finding_has_all_required_fields():
    findings = scan_text("Card: 4111111111111111")
    assert len(findings) > 0
    f = findings[0]
    required = {"type", "pattern_id", "file", "line", "column", "masked_value", "compliance", "severity"}
    assert required.issubset(set(f.keys()))


# --- JSON output format tests ---


def test_json_output_is_valid_json():
    findings = scan_text("Card: 4111111111111111")
    output = format_json(findings)
    parsed = json.loads(output)
    assert isinstance(parsed, dict)


def test_json_output_has_version():
    findings = scan_text("Card: 4111111111111111")
    parsed = json.loads(format_json(findings))
    assert "version" in parsed
    assert isinstance(parsed["version"], str)


def test_json_output_has_stable_schema():
    findings = scan_text("export AWS_KEY=AKIAIOSFODNN7EXAMPLE")
    parsed = json.loads(format_json(findings))
    assert parsed["schema"] == "leakwall-v1"
    assert "findings" in parsed
    assert "total" in parsed
    assert parsed["total"] == len(parsed["findings"])


def test_json_finding_fields():
    findings = scan_text("export AWS_KEY=AKIAIOSFODNN7EXAMPLE")
    parsed = json.loads(format_json(findings))
    f = parsed["findings"][0]
    for key in ("file", "line", "column", "pattern_id", "severity", "masked_value"):
        assert key in f, f"Missing key in JSON finding: {key}"


def test_json_output_empty_when_clean():
    findings = scan_text("clean text")
    parsed = json.loads(format_json(findings))
    assert parsed["total"] == 0
    assert parsed["findings"] == []


def test_json_multiple_findings():
    text = "password=S3cret!Pass\n123-45-6789"
    findings = scan_text(text)
    parsed = json.loads(format_json(findings))
    assert parsed["total"] >= 2
    assert len(parsed["findings"]) == parsed["total"]


# --- SARIF output format tests ---


def test_sarif_output_is_valid_json():
    findings = scan_text("Card: 4111111111111111")
    output = format_sarif(findings)
    parsed = json.loads(output)
    assert isinstance(parsed, dict)


def test_sarif_version_is_2_1_0():
    findings = scan_text("Card: 4111111111111111")
    parsed = json.loads(format_sarif(findings))
    assert parsed["version"] == "2.1.0"


def test_sarif_has_schema():
    findings = scan_text("Card: 4111111111111111")
    parsed = json.loads(format_sarif(findings))
    assert "$schema" in parsed
    assert "sarif" in parsed["$schema"]


def test_sarif_has_runs_results_rules():
    findings = scan_text("password=S3cret!Pass")
    parsed = json.loads(format_sarif(findings))
    assert "runs" in parsed
    assert len(parsed["runs"]) == 1
    run = parsed["runs"][0]
    assert "tool" in run
    assert "driver" in run["tool"]
    assert "rules" in run["tool"]["driver"]
    assert "results" in run
    assert len(run["results"]) > 0


def test_sarif_rules_are_unique():
    findings = scan_text("password=S3cret!Pass")
    parsed = json.loads(format_sarif(findings))
    rules = parsed["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = [r["id"] for r in rules]
    assert len(rule_ids) == len(set(rule_ids)), "Duplicate rule IDs found"


def test_sarif_result_structure():
    findings = scan_text("export AWS_KEY=AKIAIOSFODNN7EXAMPLE")
    parsed = json.loads(format_sarif(findings))
    result = parsed["runs"][0]["results"][0]
    assert "ruleId" in result
    assert "level" in result
    assert "message" in result
    assert "text" in result["message"]
    assert "locations" in result
    loc = result["locations"][0]["physicalLocation"]
    assert "artifactLocation" in loc
    assert "uri" in loc["artifactLocation"]
    assert "region" in loc
    assert "startLine" in loc["region"]
    assert "startColumn" in loc["region"]


def test_sarif_empty_results_when_clean():
    findings = scan_text("nothing sensitive here")
    parsed = json.loads(format_sarif(findings))
    assert parsed["runs"][0]["results"] == []


def test_sarif_critical_maps_to_error_level():
    findings = scan_text("export AWS_KEY=AKIAIOSFODNN7EXAMPLE")
    parsed = json.loads(format_sarif(findings))
    aws_results = [r for r in parsed["runs"][0]["results"] if r["ruleId"] == "AWS_KEY"]
    assert len(aws_results) > 0
    assert aws_results[0]["level"] == "error"


def test_sarif_high_maps_to_warning_level():
    findings = scan_text("Patient SSN: 123-45-6789")
    parsed = json.loads(format_sarif(findings))
    ssn_results = [r for r in parsed["runs"][0]["results"] if r["ruleId"] == "SSN"]
    assert len(ssn_results) > 0
    assert ssn_results[0]["level"] == "warning"


def test_sarif_tool_driver_info():
    findings = scan_text("clean")
    parsed = json.loads(format_sarif(findings))
    driver = parsed["runs"][0]["tool"]["driver"]
    assert driver["name"] == "LeakWall"
    assert "version" in driver
    assert "informationUri" in driver


# --- Text output format tests ---


def test_text_output_no_leaks():
    findings = scan_text("clean")
    output = format_text(findings)
    assert "No leaks" in output


def test_text_output_with_leaks_shows_type():
    findings = scan_text("password=SuperSecret123")
    output = format_text(findings)
    assert "PASSWORD_ASSIGN" in output


def test_text_output_with_leaks_shows_count():
    findings = scan_text("password=SuperSecret123")
    output = format_text(findings)
    assert "1" in output
    assert "leak" in output.lower()


def test_text_output_shows_compliance():
    findings = scan_text("123-45-6789")
    output = format_text(findings)
    assert "HIPAA" in output
