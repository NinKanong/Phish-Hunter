from __future__ import annotations

import csv
import io
from typing import Any

from ..schema import NormalizedEvent


def _value(row: dict[str, Any], *names: str) -> Any:
    for name in names:
        value = row.get(name)
        if value not in (None, "", "-"):
            return value
    return None


def _int(value: Any) -> int | None:
    try:
        return int(float(value)) if value not in (None, "", "-") else None
    except (TypeError, ValueError):
        return None


def parse_zeek(text: str, filename: str = "conn.log") -> list[NormalizedEvent]:
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return []
    fields = None
    for line in lines[:20]:
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
            break
    events: list[NormalizedEvent] = []
    if fields:
        body = "\n".join(line for line in lines if not line.startswith("#"))
        reader = csv.DictReader(io.StringIO(body), fieldnames=fields, delimiter="\t")
        for row in reader:
            events.append(_normalize(row, filename))
        return events
    # Zeek JSON logs are accepted as newline-delimited JSON by the generic caller.
    return events


def _normalize(row: dict[str, Any], filename: str) -> NormalizedEvent:
    name = filename.lower()
    event_type = "zeek_conn"
    if "dns" in name:
        event_type = "zeek_dns"
    elif "http" in name:
        event_type = "zeek_http"
    elif "ssl" in name or "tls" in name:
        event_type = "zeek_ssl"
    elif "smb" in name:
        event_type = "zeek_smb"
    elif "kerberos" in name:
        event_type = "zeek_kerberos"
    return NormalizedEvent(
        timestamp=_value(row, "ts", "timestamp"),
        source="zeek",
        event_type=event_type,
        src_ip=_value(row, "id.orig_h", "src_ip", "src"),
        src_port=_int(_value(row, "id.orig_p", "src_port", "sport")),
        dst_ip=_value(row, "id.resp_h", "dst_ip", "dst"),
        dst_port=_int(_value(row, "id.resp_p", "dst_port", "dport")),
        protocol=_value(row, "proto", "protocol", "service"),
        hostname=_value(row, "host", "query", "server_name", "server_name"),
        action=_value(row, "conn_state", "method", "action"),
        bytes=_int(_value(row, "orig_bytes", "bytes", "request_body_len")),
        packets=_int(_value(row, "orig_pkts", "packets")),
        message=_value(row, "uri", "query", "msg"),
        raw=dict(row),
    )
