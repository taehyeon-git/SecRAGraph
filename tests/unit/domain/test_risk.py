from security_review.domain.models import Confidence, Finding, Severity
from security_review.domain.risk import calculate_risk


def finding(identifier: str, severity: Severity) -> Finding:
    return Finding(
        id=identifier,
        rule_id=identifier.split(":", maxsplit=1)[0],
        category="code_pattern",
        severity=severity,
        file_path="src/app.py",
        line_start=1,
        message="Risk detected",
        redacted_evidence="safe evidence",
        confidence=Confidence.HIGH,
        remediation="Use a safer API.",
    )


def test_empty_findings_have_zero_low_risk() -> None:
    result = calculate_risk([])
    assert result.score == 0
    assert result.level == Severity.LOW
    assert result.counts == {severity: 0 for severity in Severity}


def test_risk_score_uses_documented_weights() -> None:
    result = calculate_risk(
        [
            finding("INFO:1", Severity.INFO),
            finding("LOW:1", Severity.LOW),
            finding("MEDIUM:1", Severity.MEDIUM),
            finding("HIGH:1", Severity.HIGH),
            finding("CRITICAL:1", Severity.CRITICAL),
        ]
    )
    assert result.score == 23
    assert result.level == Severity.CRITICAL
    assert result.counts == {severity: 1 for severity in Severity}


def test_risk_threshold_boundaries() -> None:
    assert calculate_risk([finding("LOW:1", Severity.LOW)]).level == Severity.LOW
    assert calculate_risk([finding("MEDIUM:1", Severity.MEDIUM)]).level == Severity.MEDIUM
    assert calculate_risk([finding("HIGH:1", Severity.HIGH)]).level == Severity.HIGH
    assert (
        calculate_risk(
            [
                finding("HIGH:1", Severity.HIGH),
                finding("HIGH:2", Severity.HIGH),
                finding("LOW:1", Severity.LOW),
            ]
        ).level
        == Severity.CRITICAL
    )
