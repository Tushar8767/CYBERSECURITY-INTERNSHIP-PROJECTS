from __future__ import annotations

from core.correlation_engine import STAGE_BY_RULE
from models.schemas import Alert, Event


def build_timeline(events: list[Event], alerts: list[Alert]) -> list[dict[str, object]]:
    by_id = {e.event_id: e for e in events}
    items: list[dict[str, object]] = []
    for alert in alerts:
        evidence = [by_id[eid] for eid in alert.evidence_event_ids if eid in by_id]
        time = min((e.timestamp for e in evidence if e.timestamp), default=alert.first_seen)
        items.append(
            {
                "timestamp": time,
                "stage": STAGE_BY_RULE.get(alert.rule_id, alert.alert_name),
                "alert_id": alert.alert_id,
                "rule_id": alert.rule_id,
                "event_ids": alert.evidence_event_ids,
                "description": alert.description,
            }
        )
    return sorted(items, key=lambda item: item["timestamp"] or "")
