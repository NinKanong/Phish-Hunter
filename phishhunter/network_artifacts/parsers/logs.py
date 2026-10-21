from __future__ import annotations

import csv
import io
import json
import re
from typing import Any

from ..schema import NormalizedEvent

_IP = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"


def parse_log(text: str, artifact_type: str, filename: str) -> list[NormalizedEvent]:
    events: list[NormalizedEvent] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        obj: dict[str, Any] | None = None
        try:
            value = json.loads(line)
            if isinstance(value, dict):
                obj = value
        except json.JSONDecodeError:
            obj = None
        if obj:
            events.append(_json_event(obj, artifact_type))
            continue
        events.append(_text_event(line, artifact_type, filename))
    return events


def _json_event(obj: dict[str, Any], artifact_type: str) -> NormalizedEvent:
    def pick(*names: str):
        for n in names:
            if obj.get(n) not in (None, "", "-"):
                return obj[n]
        return None
    return NormalizedEvent(
        timestamp=pick("timestamp", "time", "ts", "datetime"), source=artifact_type, event_type=artifact_type,
        src_ip=pick("src_ip", "src", "source", "source_ip"), dst_ip=pick("dst_ip", "dst", "destination", "destination_ip"),
        src_port=_to_int(pick("src_port", "sport", "source_port")), dst_port=_to_int(pick("dst_port", "dport", "destination_port")),
        protocol=pick("protocol", "proto"), hostname=pick("hostname", "host", "domain", "query"),
        action=pick("action", "decision", "verdict", "status"), severity=pick("severity", "level"),
        bytes=_to_int(pick("bytes", "size")), message=pick("message", "msg", "reason"), raw=obj,
    )


def _text_event(line: str, artifact_type: str, filename: str) -> NormalizedEvent:
    ips = re.findall(_IP, line)
    ports = [int(x) for x in re.findall(r"(?:port[=:\s]+|:)(\d{1,5})\b", line, re.I) if int(x) <= 65535]
    return NormalizedEvent(
        source=artifact_type, event_type=artifact_type,
        src_ip=ips[0] if ips else None, dst_ip=ips[1] if len(ips) > 1 else None,
        src_port=ports[0] if ports else None, dst_port=ports[1] if len(ports) > 1 else None,
        message=line[:4000], raw={"line": line, "filename": filename},
    )


def _to_int(value: Any) -> int | None:
    try:
        return int(value) if value not in (None, "", "-") else None
    except (TypeError, ValueError):
        return None
