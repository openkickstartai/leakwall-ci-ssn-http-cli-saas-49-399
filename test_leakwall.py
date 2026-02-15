"""Tests for LeakWall sensitive data leak detection engine."""
from leakwall import luhn_check, scan_text


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
    assert len(cs) >= 1
    assert cs[0]["severity"] == "CRITICAL"


def test_private_key_detected():
    findings = scan_text("-----BEGIN RSA PRIVATE KEY-----")
    pk = [f for f in findings if f["type"] == "PRIVATE_KEY"]
    assert len(pk) == 1


def test_password_assignment_detected():
    findings = scan_text("config: password=MyS3cretP@ss")
    pw = [f for f in findings if f["type"] == "PASSWORD_ASSIGN"]
    assert len(pw) >= 1


def test_clean_text_no_leaks():
    findings = scan_text("INFO 2024-01-15 Application started on port 8080")
    assert len(findings) == 0


def test_clean_prose_no_false_positives():
    findings = scan_text("The user logged in successfully and viewed the dashboard.")
    assert len(findings) == 0


def test_luhn_algorithm_valid():
    assert luhn_check("4111111111111111") is True
    assert luhn_check("5500000000000004") is True
    assert luhn_check("378282246310005") is True  # Amex


def test_luhn_algorithm_invalid():
    assert luhn_check("1234567890123456") is False
    assert luhn_check("0000") is False
    assert luhn_check("111") is False


def test_multiline_reports_correct_lines():
    text = "line 1 ok\nSSN: 123-45-6789\nkey: AKIAIOSFODNN7EXAMPLE"
    findings = scan_text(text)
    assert len(findings) >= 2
    lines = {f["line"] for f in findings}
    assert 2 in lines
    assert 3 in lines


def test_masked_value_hides_secret():
    findings = scan_text("key=AKIAIOSFODNN7EXAMPLE")
    aws = [f for f in findings if f["type"] == "AWS_KEY"]
    assert len(aws) == 1
    assert "AKIAIOSFODNN7EXAMPLE" not in aws[0]["masked_value"]
    assert "****" in aws[0]["masked_value"]
