from __future__ import annotations

from config.constants import SEVERITY_ORDER
from models.schemas import Alert


def severity_from_score(score: int) -> str:
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


def score_alerts(alerts: list[Alert]) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    for alert in alerts:
        score += alert.risk_score
        reasons.append(f"{alert.rule_id}: +{alert.risk_score}")
    if len({a.rule_id for a in alerts}) >= 4:
        score += 20
        reasons.append("Multi-stage correlation bonus: +20")
    return min(score, 100), reasons


def max_severity(values: list[str]) -> str:
    return max(values or ["Low"], key=lambda item: SEVERITY_ORDER.get(item, 0))
