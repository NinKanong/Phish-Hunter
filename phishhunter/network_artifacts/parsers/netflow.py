from __future__ import annotations

import csv
import io
import json
from typing import Any

from ..schema import NormalizedEvent


def _int(value: Any) -> int | None:
    try:
        return int(float(value)) if value not in (None, "", "-") else None
    except (TypeError, ValueError):
        return None


def _pick(row: dict[str, Any], *names: str) -> Any:
    lowered = {str(k).lower(): v for k, v in row.items()}
    for name in names:
        value = lowered.get(name.lower())
        if value not in (None, "", "-"):
            return value
    return None


def parse_netflow(text: str) -> list[NormalizedEvent]:
    events: list[NormalizedEvent] = []
    try:
        parsed = json.loads(text)
        records = parsed if isinstance(parsed, list) else parsed.get("records", []) if isinstance(parsed, dict) else []
        if records:
            for row in records:
                if isinstance(row, dict):
                    events.append(_row(row))
            return events
    except json.JSONDecodeError:
        pass
    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        events.append(_row(row))
    return events


def _row(row: dict[str, Any]) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=_pick(row, "timestamp", "ts", "first_switched", "first_seen"),
        source="netflow", event_type="netflow",
        src_ip=_pick(row, "src", "src_ip", "source_address", "sourceip"),
        src_port=_int(_pick(row, "sport", "src_port", "source_port")),
        dst_ip=_pick(row, "dst", "dst_ip", "destination_address", "destinationip"),
        dst_port=_int(_pick(row, "dport", "dst_port", "destination_port")),
        protocol=_pick(row, "proto", "protocol"), bytes=_int(_pick(row, "bytes", "in_bytes", "out_bytes")),
        packets=_int(_pick(row, "packets", "in_pkts", "out_pkts")), raw=row,
    )
