from __future__ import annotations

from security_agent.config import Thresholds
from security_agent.models import Finding, Reachability


SEVERITY_SCORE = {"CRITICAL": 9.5, "HIGH": 8.0, "MODERATE": 5.5, "MEDIUM": 5.5, "LOW": 3.0, "UNKNOWN": 0.0}


def prioritize(finding: Finding, thresholds: Thresholds) -> Finding:
    """Apply a transparent 0-100 risk score; no probabilistic judgment happens here."""
    base = finding.advisory.cvss
    if base is None:
        base = SEVERITY_SCORE.get(finding.advisory.severity, 0.0)
    score = min(max(base, 0), 10) * 4
    score += (finding.epss or 0) * 25
    score += 30 if finding.kev else 0
    score += 8 if finding.dependency.direct else 0
    score += 0 if finding.dependency.development else 7
    score += {
        Reachability.REACHABLE: 10,
        Reachability.POSSIBLE: 5,
        Reachability.UNREACHABLE: -10,
        Reachability.UNKNOWN: 0,
    }[finding.triage.reachability]
    finding.priority = round(min(max(score, 0), 100), 1)
    if finding.kev or finding.advisory.severity == "CRITICAL" or finding.priority >= thresholds.immediate:
        finding.disposition = "immediate"
    elif finding.priority >= thresholds.digest:
        finding.disposition = "digest"
    else:
        finding.disposition = "log"
    return finding

