from __future__ import annotations

from dataclasses import dataclass
from typing import List

from .rules import Finding, SEVERITY_WEIGHT


@dataclass
class ScanResult:
    repo_id: str
    findings: List[Finding]
    score: int
    risk_level: str
    scan_complete: bool = True
    incomplete_reasons: List[str] | None = None


def score_findings(findings: List[Finding]) -> tuple[int, str]:
    # Diminishing returns per additional finding of the same category so
    # one noisy file doesn't single-handedly max out the score.
    seen_categories: dict[str, int] = {}
    total = 0
    for f in findings:
        count = seen_categories.get(f.category, 0)
        weight = SEVERITY_WEIGHT[f.severity]
        total += weight * (0.6 ** count)
        seen_categories[f.category] = count + 1

    score = min(100, round(total))

    if score >= 70:
        level = "CRITICAL"
    elif score >= 40:
        level = "HIGH"
    elif score >= 15:
        level = "MEDIUM"
    elif score > 0:
        level = "LOW"
    else:
        level = "CLEAN"
    return score, level


def build_result(
    repo_id: str, findings: List[Finding], incomplete_reasons: List[str] | None = None
) -> ScanResult:
    score, level = score_findings(findings)
    reasons = incomplete_reasons or []
    return ScanResult(
        repo_id=repo_id,
        findings=findings,
        score=score,
        risk_level=level,
        scan_complete=not reasons,
        incomplete_reasons=reasons,
    )
