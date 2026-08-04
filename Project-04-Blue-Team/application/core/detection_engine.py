from __future__ import annotations

import json
from collections import defaultdict
from datetime import timedelta
from pathlib import Path

from config.settings import settings
from models.schemas import Alert, Event


def _windowed(events: list[Event], minutes: int) -> list[list[Event]]:
    ordered = sorted([e for e in events if e.timestamp], key=lambda e: e.timestamp)
    groups: list[list[Event]] = []
    for i, event in enumerate(ordered):
        group = [e for e in ordered[i:] if e.timestamp and event.timestamp and e.timestamp <= event.timestamp + timedelta(minutes=minutes)]
        groups.append(group)
    return groups


class DetectionEngine:
    def __init__(self, rules_path: Path | None = None) -> None:
        self.rules_path = rules_path or settings.rules_dir / "detection_rules.json"
        self.rules = json.loads(self.rules_path.read_text(encoding="utf-8"))["rules"]

    def run(self, events: list[Event], investigation_id: str) -> list[Alert]:
        alerts: list[Alert] = []
        alerts.extend(self._repeated_failures(events, investigation_id))
        alerts.extend(self._username_enum(events, investigation_id))
        alerts.extend(self._success_after_failures(events, investigation_id))
        alerts.extend(self._simple_event_alerts(events, investigation_id))
        seen: set[tuple[str, str, str | None]] = set()
        deduped: list[Alert] = []
        for alert in alerts:
            key = (alert.rule_id, ",".join(alert.evidence_event_ids), alert.source_ip)
            if key not in seen:
                deduped.append(alert)
                seen.add(key)
        for alert in deduped:
            for event in events:
                if event.event_id in alert.evidence_event_ids and alert.rule_id not in event.matched_rule_ids:
                    event.matched_rule_ids.append(alert.rule_id)
                    if alert.severity in {"High", "Critical"}:
                        event.classification = "Critical"
                        event.severity = alert.severity
                    else:
                        event.classification = "Suspicious"
                        event.severity = alert.severity
        return deduped

    def _rule(self, rule_id: str) -> dict:
        return next(r for r in self.rules if r["rule_id"] == rule_id)

    def _alert(self, rule_id: str, events: list[Event], investigation_id: str, source_ip: str | None = None) -> Alert:
        rule = self._rule(rule_id)
        times = [e.timestamp for e in events if e.timestamp]
        return Alert(
            investigation_id=investigation_id,
            rule_id=rule_id,
            alert_name=rule["name"],
            first_seen=min(times) if times else None,
            last_seen=max(times) if times else None,
            hostname=events[0].hostname if events else None,
            source_ip=source_ip or (events[0].source_ip if events else None),
            affected_username=events[-1].username if events else None,
            event_count=len(events),
            severity=rule["default_severity"],
            risk_score=rule["risk_contribution"],
            confidence=rule["confidence"],
            description=rule["alert_reason"],
            evidence_event_ids=[e.event_id for e in events],
            possible_impact=rule["possible_impact"],
            recommended_actions=rule["recommended_response"],
        )

    def _repeated_failures(self, events: list[Event], investigation_id: str) -> list[Alert]:
        by_ip: dict[str, list[Event]] = defaultdict(list)
        for event in events:
            if event.event_type == "ssh_failed_password" and event.source_ip:
                by_ip[event.source_ip].append(event)
        alerts: list[Alert] = []
        for ip, ip_events in by_ip.items():
            for group in _windowed(ip_events, 5):
                if len(group) >= 5:
                    alerts.append(self._alert("AUTH-001", group[:5], investigation_id, ip))
                    break
        return alerts

    def _username_enum(self, events: list[Event], investigation_id: str) -> list[Alert]:
        by_ip: dict[str, list[Event]] = defaultdict(list)
        for event in events:
            if event.event_type == "ssh_invalid_user" and event.source_ip:
                by_ip[event.source_ip].append(event)
        alerts: list[Alert] = []
        for ip, ip_events in by_ip.items():
            for group in _windowed(ip_events, 10):
                if len({e.username for e in group}) >= 5:
                    alerts.append(self._alert("AUTH-002", group, investigation_id, ip))
                    break
        return alerts

    def _success_after_failures(self, events: list[Event], investigation_id: str) -> list[Alert]:
        failures = [e for e in events if e.event_type in {"ssh_failed_password", "ssh_invalid_user"} and e.timestamp]
        alerts = []
        for success in [e for e in events if e.event_type == "ssh_accepted" and e.timestamp and e.source_ip]:
            prior = [
                f for f in failures
                if f.source_ip == success.source_ip and f.timestamp and success.timestamp
                and success.timestamp - timedelta(minutes=30) <= f.timestamp < success.timestamp
            ]
            if len(prior) >= 3:
                alert = self._alert("AUTH-003", [*prior, success], investigation_id, success.source_ip)
                if success.authentication_method == "password" or (success.timestamp and success.timestamp.hour < 5):
                    alert.severity = "High"
                    alert.risk_score += 10
                alerts.append(alert)
        return alerts

    def _simple_event_alerts(self, events: list[Event], investigation_id: str) -> list[Alert]:
        mapping = {
            "sudo_command": ("PRIV-001", lambda e: e.command and e.command.strip() in {"/bin/bash", "/bin/sh", "sudo -s", "sudo -i"}),
            "user_created": ("ACCOUNT-001", lambda e: True),
            "privileged_group_added": ("PRIV-002", lambda e: True),
            "sudoers_modified": ("PRIV-003", lambda e: True),
            "cron_modified": ("PERSIST-001", lambda e: True),
            "history_cleared": ("EVASION-001", lambda e: True),
        }
        alerts: list[Alert] = []
        for event in events:
            if event.event_type == "ssh_accepted" and event.authentication_method == "password" and event.timestamp and 0 <= event.timestamp.hour < 5:
                alerts.append(self._alert("AUTH-004", [event], investigation_id, event.source_ip))
            if event.command and ("curl" in event.command or "wget" in event.command) and "|" in event.command:
                alerts.append(self._alert("PERSIST-002", [event], investigation_id, event.source_ip))
            rule_info = mapping.get(event.event_type)
            if rule_info and rule_info[1](event):
                alerts.append(self._alert(rule_info[0], [event], investigation_id, event.source_ip))
        created = {e.username for e in events if e.event_type == "user_created"}
        for event in events:
            if event.event_type == "ssh_accepted" and event.username in created:
                alerts.append(self._alert("AUTH-005", [event], investigation_id, event.source_ip))
        return alerts
