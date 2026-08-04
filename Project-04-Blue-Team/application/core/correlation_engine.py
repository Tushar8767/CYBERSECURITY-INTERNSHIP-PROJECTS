from __future__ import annotations

from core.recommendations import recovery_actions
from core.scoring_engine import score_alerts, severity_from_score
from models.schemas import Alert, Incident

STAGE_BY_RULE = {
    "AUTH-002": "Username enumeration",
    "AUTH-001": "Repeated login failures",
    "AUTH-003": "Account compromise",
    "AUTH-004": "Unusual-hours login",
    "AUTH-005": "Backdoor-account reuse",
    "ACCOUNT-001": "Account creation",
    "PRIV-001": "Root shell obtained",
    "PRIV-002": "Privileged-group modification",
    "PRIV-003": "Sudoers modification",
    "PERSIST-001": "Suspicious cron persistence",
    "PERSIST-002": "Remote script piped to shell",
    "EVASION-001": "Defense evasion",
}


def correlate_alerts(alerts: list[Alert]) -> list[Incident]:
    if not alerts:
        return []
    times = [t for a in alerts for t in [a.first_seen, a.last_seen] if t]
    score, reasons = score_alerts(alerts)
    source_ips = sorted({a.source_ip for a in alerts if a.source_ip})
    users = sorted({u for a in alerts for u in [a.affected_username, a.target_username] if u})
    stages = [STAGE_BY_RULE.get(a.rule_id, a.alert_name) for a in alerts]
    title = "SSH Brute-Force Compromise, Privilege Escalation, and Persistence" if len(set(stages)) >= 4 else "Security Authentication Incident"
    return [
        Incident(
            title=title,
            summary=f"Correlated {len(alerts)} alert(s) into one investigation chain. Score factors: {', '.join(reasons)}.",
            first_seen=min(times) if times else None,
            last_seen=max(times) if times else None,
            hostname=next((a.hostname for a in alerts if a.hostname), None),
            source_ips=source_ips,
            affected_users=users,
            related_alert_ids=[a.alert_id for a in alerts],
            related_event_ids=sorted({eid for a in alerts for eid in a.evidence_event_ids}),
            severity=severity_from_score(score),
            risk_score=score,
            confidence=max(a.confidence for a in alerts),
            attack_stages=list(dict.fromkeys(stages)),
            possible_impact="Unauthorized access, privilege escalation, persistence, and evidence tampering are possible.",
            recommended_response=recovery_actions(alerts),
            recovery_actions=recovery_actions(alerts),
        )
    ]
