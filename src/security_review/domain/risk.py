"""Deterministic risk scoring policy."""

from collections import Counter
from collections.abc import Sequence

from security_review.domain.models import Finding, RiskSummary, Severity

_WEIGHTS: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 3,
    Severity.HIGH: 7,
    Severity.CRITICAL: 12,
}


def calculate_risk(findings: Sequence[Finding]) -> RiskSummary:
    """Calculate a stable risk score from normalized finding severities."""

    counts = Counter(item.severity for item in findings)
    score = sum(_WEIGHTS[severity] * count for severity, count in counts.items())
    if score >= 15:
        level = Severity.CRITICAL
    elif score >= 7:
        level = Severity.HIGH
    elif score >= 2:
        level = Severity.MEDIUM
    else:
        level = Severity.LOW
    return RiskSummary(
        score=score,
        level=level,
        counts={severity: counts[severity] for severity in Severity},
    )
