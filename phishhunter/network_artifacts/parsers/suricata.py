from __future__ import annotations

import json
from typing import Any

from ..schema import NormalizedEvent


def _int(value: Any) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def parse_suricata(text: str) -> list[NormalizedEvent]:
    events: list[NormalizedEvent] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        flow = obj.get("flow") or {}
        alert = obj.get("alert") or {}
        events.append(NormalizedEvent(
            timestamp=obj.get("timestamp"), source="suricata", event_type=str(obj.get("event_type", "eve")),
            src_ip=obj.get("src_ip"), src_port=_int(obj.get("src_port")),
            dst_ip=obj.get("dest_ip"), dst_port=_int(obj.get("dest_port")),
            protocol=obj.get("proto"), hostname=(obj.get("http") or {}).get("hostname") or (obj.get("tls") or {}).get("sni"),
            action=alert.get("action") or flow.get("state"), severity=alert.get("severity"),
            bytes=_int(flow.get("bytes_toserver")), packets=_int(flow.get("pkts_toserver")),
            message=alert.get("signature") or obj.get("event_type"), raw=obj,
        ))
    return events
