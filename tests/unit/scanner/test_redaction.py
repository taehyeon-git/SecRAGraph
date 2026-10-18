from security_review.scanner.redaction import safe_evidence


def test_safe_evidence_never_contains_scanned_source() -> None:
    secret = "sk-test-1234567890"
    for rule_id in ("SEC001", "PY001", "PY002", "PY003", "PY004", "JS001"):
        assert secret not in safe_evidence(rule_id)
    assert "***REDACTED***" in safe_evidence("SEC001")


def test_unknown_rule_uses_source_free_fallback() -> None:
    assert safe_evidence("third-party-rule") == "Pattern detected; source omitted for privacy."
