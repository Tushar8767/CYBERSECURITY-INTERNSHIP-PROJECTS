from __future__ import annotations

from models.schemas import Alert


def recovery_actions(alerts: list[Alert]) -> list[str]:
    actions = {
        "Preserve forensic evidence and export the incident report.",
        "Review authentication logs around the incident window.",
        "Apply least privilege and monitor privileged account changes.",
    }
    rule_ids = {a.rule_id for a in alerts}
    if {"AUTH-001", "AUTH-002", "AUTH-003"} & rule_ids:
        actions.update({"Block malicious source IPs after approval.", "Reset affected account passwords.", "Enable MFA and restrict SSH access."})
    if {"PRIV-001", "PRIV-002", "PRIV-003"} & rule_ids:
        actions.update({"Remove unauthorized sudo access.", "Restore /etc/sudoers from a trusted baseline.", "Rotate SSH keys for affected accounts."})
    if {"PERSIST-001", "PERSIST-002"} & rule_ids:
        actions.update({"Remove malicious cron jobs.", "Inspect downloaded scripts in an isolated forensic workflow."})
    if "EVASION-001" in rule_ids:
        actions.add("Create alerts for shell-history deletion.")
    return sorted(actions)
