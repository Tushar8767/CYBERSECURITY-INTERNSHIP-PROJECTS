from __future__ import annotations

import re
from collections import defaultdict

from models.schemas import Event, Indicator

PATTERNS = {
    "IPv4": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "IPv6": r"\b(?:[a-fA-F0-9]{1,4}:){2,7}[a-fA-F0-9]{1,4}\b",
    "URL": r"https?://[^\s'\"]+",
    "Email": r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b",
    "MD5": r"\b[a-fA-F0-9]{32}\b",
    "SHA1": r"\b[a-fA-F0-9]{40}\b",
    "SHA256": r"\b[a-fA-F0-9]{64}\b",
    "CVE": r"\bCVE-\d{4}-\d{4,7}\b",
    "Domain": r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b",
}


def extract_iocs(events: list[Event]) -> list[Indicator]:
    buckets: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for event in events:
        text = " ".join(filter(None, [event.raw_message, event.source_ip, event.command]))
        for typ, pattern in PATTERNS.items():
            for value in re.findall(pattern, text):
                if typ == "Domain" and (value.startswith("CVE-") or "@" in value):
                    continue
                buckets[(typ, value)].append(event)
    indicators: list[Indicator] = []
    for (typ, value), related in buckets.items():
        times = [e.timestamp for e in related if e.timestamp]
        indicators.append(
            Indicator(
                indicator=value,
                indicator_type=typ,
                first_seen=min(times) if times else None,
                last_seen=max(times) if times else None,
                event_count=len(related),
            )
        )
    return indicators
