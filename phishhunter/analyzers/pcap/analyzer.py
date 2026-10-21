from __future__ import annotations

import ipaddress
import struct
from collections import Counter, defaultdict
from datetime import datetime, timezone

from phishhunter_common.ioc import extract_iocs


def _ipv4(raw: bytes) -> str:
    try:
        return str(ipaddress.IPv4Address(raw))
    except ipaddress.AddressValueError:
        return "0.0.0.0"


def _ipv6(raw: bytes) -> str:
    try:
        return str(ipaddress.IPv6Address(raw))
    except ipaddress.AddressValueError:
        return "::"


def _ip_scope(value: str | None) -> str:
    if not value:
        return "unknown"
    try:
        ip = ipaddress.ip_address(value)
        if ip.is_private:
            return "private"
        if ip.is_loopback:
            return "loopback"
        if ip.is_link_local:
            return "link-local"
        if ip.is_multicast:
            return "multicast"
        if ip.is_reserved:
            return "reserved"
        return "public"
    except ValueError:
        return "unknown"


def _dns_name(payload: bytes, start: int, limit: int = 128) -> tuple[str, int]:
    labels = []
    pos = start
    jumped = False
    end = start
    seen = set()
    for _ in range(limit):
        if pos >= len(payload):
            break
        ln = payload[pos]
        if ln == 0:
            pos += 1
            if not jumped:
                end = pos
            break
        if ln & 0xC0 == 0xC0 and pos + 1 < len(payload):
            ptr = ((ln & 0x3F) << 8) | payload[pos + 1]
            if not jumped:
                end = pos + 2
            if ptr in seen:
                break
            seen.add(ptr)
            pos = ptr
            jumped = True
            continue
        if ln > 63 or pos + 1 + ln > len(payload):
            break
        labels.append(payload[pos + 1:pos + 1 + ln].decode("utf-8", "replace"))
        pos += ln + 1
        if not jumped:
            end = pos
    return ".".join(labels), end or min(len(payload), start + 1)


def _dns_details(payload: bytes, udp_payload_offset: int) -> dict:
    data = payload[udp_payload_offset:]
    if len(data) < 12:
        return {}
    txid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    pos = 12
    questions = []
    for _ in range(min(qd, 32)):
        name, pos2 = _dns_name(data, pos)
        pos = pos2
        if pos + 4 > len(data):
            break
        qtype, qclass = struct.unpack("!HH", data[pos:pos + 4])
        pos += 4
        questions.append({"name": name, "type": {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT"}.get(qtype, str(qtype)), "class": qclass})
    answers = []
    for _ in range(min(an + ns + ar, 128)):
        name, pos2 = _dns_name(data, pos)
        pos = pos2
        if pos + 10 > len(data):
            break
        typ, cls, ttl, rdlen = struct.unpack("!HHIH", data[pos:pos + 10])
        pos += 10
        if pos + rdlen > len(data):
            break
        rstart = pos
        value = None
        if typ in (1, 28):
            try:
                value = str(ipaddress.ip_address(data[rstart:rstart + rdlen]))
            except ValueError:
                value = None
        elif typ in (5, 2):
            value, _ = _dns_name(data, rstart)
        elif typ == 16:
            p = rstart
            parts = []
            while p < rstart + rdlen:
                ln = data[p]
                p += 1
                parts.append(data[p:p + ln].decode("utf-8", "replace"))
                p += ln
            value = "".join(parts)
        answers.append({"name": name, "type": {1: "A", 28: "AAAA", 5: "CNAME", 2: "NS", 15: "MX", 16: "TXT"}.get(typ, str(typ)), "ttl": ttl, "value": value})
        pos += rdlen
    return {"transaction_id": txid, "flags": hex(flags), "questions": questions, "answers": answers}


def _http_details(payload: bytes) -> dict | None:
    if not payload:
        return None
    text = payload[:32768].decode("latin1", "ignore")
    first = text.split("\r\n", 1)[0]
    if not (first.startswith(("GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "PATCH ", "OPTIONS ", "CONNECT ", "HTTP/1."))):
        return None
    headers = {}
    for line in text.split("\r\n")[1:80]:
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers[k.strip().lower()] = v.strip()[:512]
    request = first if len(first) < 2048 else first[:2048]
    return {
        "request_line": request,
        "host": headers.get("host"),
        "user_agent": headers.get("user-agent"),
        "content_type": headers.get("content-type"),
        "server": headers.get("server"),
        "location": headers.get("location"),
    }


def _tls_sni(payload: bytes) -> str | None:
    # Minimal TLS ClientHello SNI parser; deliberately bounded and passive.
    if len(payload) < 5 or payload[0] != 22 or payload[1:3] != b"\x03\x03":
        return None
    try:
        record_len = struct.unpack("!H", payload[3:5])[0]
        data = payload[5:5 + min(record_len, 65535)]
        if len(data) < 42 or data[0] != 1:
            return None
        hs_len = int.from_bytes(data[1:4], "big")
        hello = data[4:4 + hs_len]
        if len(hello) < 38:
            return None
        pos = 34
        session_len = hello[pos]
        pos += 1 + session_len
        if pos + 2 > len(hello):
            return None
        cipher_len = struct.unpack("!H", hello[pos:pos + 2])[0]
        pos += 2 + cipher_len
        if pos >= len(hello):
            return None
        comp_len = hello[pos]
        pos += 1 + comp_len
        if pos + 2 > len(hello):
            return None
        ext_len = struct.unpack("!H", hello[pos:pos + 2])[0]
        pos += 2
        end = min(len(hello), pos + ext_len)
        while pos + 4 <= end:
            etype, elen = struct.unpack("!HH", hello[pos:pos + 4])
            pos += 4
            ext = hello[pos:pos + elen]
            pos += elen
            if etype != 0 or len(ext) < 5:
                continue
            list_len = struct.unpack("!H", ext[:2])[0]
            p = 2
            stop = min(len(ext), 2 + list_len)
            while p + 3 <= stop:
                name_type = ext[p]
                name_len = struct.unpack("!H", ext[p + 1:p + 3])[0]
                p += 3
                name = ext[p:p + name_len]
                p += name_len
                if name_type == 0:
                    value = name.decode("idna", "ignore")[:255]
                    return value or None
    except (ValueError, IndexError, struct.error):
        return None
    return None


def _tcp_flags(packet: bytes, offset: int) -> dict:
    if len(packet) < offset + 14:
        return {}
    flags = packet[offset + 13]
    return {
        "fin": bool(flags & 0x01),
        "syn": bool(flags & 0x02),
        "rst": bool(flags & 0x04),
        "psh": bool(flags & 0x08),
        "ack": bool(flags & 0x10),
        "urg": bool(flags & 0x20),
    }


def _packet_fields(packet: bytes) -> dict:
    if len(packet) < 14:
        return {"protocol": "truncated", "src": None, "dst": None, "sport": None, "dport": None, "dns": None, "http": None, "tls_sni": None, "tcp_flags": {}, "payload_iocs": {}}
    offset = 14
    ethertype = struct.unpack("!H", packet[12:14])[0]
    vlan = None
    if ethertype in (0x8100, 0x88A8) and len(packet) >= 18:
        vlan = struct.unpack("!H", packet[14:16])[0] & 0x0FFF
        ethertype = struct.unpack("!H", packet[16:18])[0]
        offset = 18
    if ethertype == 0x0800:
        if len(packet) < offset + 20:
            return {"protocol": "ipv4-malformed", "src": None, "dst": None, "sport": None, "dport": None, "dns": None, "http": None, "tls_sni": None, "tcp_flags": {}, "payload_iocs": {}}
        ip = packet[offset:]
        ihl = (ip[0] & 0x0F) * 4
        if ihl < 20 or len(ip) < ihl:
            return {"protocol": "ipv4-malformed", "src": None, "dst": None, "sport": None, "dport": None, "dns": None, "http": None, "tls_sni": None, "tcp_flags": {}, "payload_iocs": {}}
        proto = ip[9]
        src, dst = _ipv4(ip[12:16]), _ipv4(ip[16:20])
        l4 = offset + ihl
    elif ethertype == 0x86DD:
        if len(packet) < offset + 40:
            return {"protocol": "ipv6-malformed", "src": None, "dst": None, "sport": None, "dport": None, "dns": None, "http": None, "tls_sni": None, "tcp_flags": {}, "payload_iocs": {}}
        ip = packet[offset:]
        proto = ip[6]
        src, dst = _ipv6(ip[8:24]), _ipv6(ip[24:40])
        l4 = offset + 40
    else:
        return {"protocol": f"ethernet/0x{ethertype:04x}", "src": None, "dst": None, "sport": None, "dport": None, "dns": None, "http": None, "tls_sni": None, "tcp_flags": {}, "payload_iocs": {}}
    names = {1: "ICMP", 6: "TCP", 17: "UDP"}
    pname = names.get(proto, f"IP/{proto}")
    sport = dport = None
    dns = None
    http = None
    tls_sni = None
    tcp_flags = {}
    transport_offset = l4
    if proto in (6, 17) and len(packet) >= l4 + 8:
        sport, dport = struct.unpack("!HH", packet[l4:l4 + 4])
        if proto == 6 and len(packet) >= l4 + 20:
            data_offset = ((packet[l4 + 12] >> 4) & 0x0F) * 4
            transport_offset = l4 + max(20, data_offset)
            tcp_flags = _tcp_flags(packet, l4)
        else:
            transport_offset = l4 + 8
        if proto == 17 and (sport == 53 or dport == 53):
            dns = _dns_details(packet, transport_offset)
    payload = packet[transport_offset:] if transport_offset <= len(packet) else b""
    if proto == 6:
        http = _http_details(payload)
        tls_sni = _tls_sni(payload)
    iocs = extract_iocs(payload[:2_000_000].decode("latin1", "ignore")) if payload else {"ips": [], "ipv4": [], "ipv6": [], "urls": [], "domains": [], "hashes": [], "emails": []}
    return {
        "protocol": pname,
        "src": src,
        "dst": dst,
        "src_scope": _ip_scope(src),
        "dst_scope": _ip_scope(dst),
        "sport": sport,
        "dport": dport,
        "vlan": vlan,
        "dns": dns,
        "http": http,
        "tls_sni": tls_sni,
        "tcp_flags": tcp_flags,
        "payload_length": len(payload),
        "payload_iocs": iocs,
    }


def _classic_pcap(data: bytes) -> tuple[int, int, list[tuple[float, bytes]]]:
    if len(data) < 24:
        raise ValueError("PCAP is shorter than the global header")
    magic = data[:4]
    endian = "<" if magic in {b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"} else ">" if magic in {b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"} else None
    if endian is None:
        raise ValueError("Unsupported PCAP format")
    _, _, _, _, _, snaplen, network = struct.unpack(endian + "IHHIIII", data[:24])
    offset = 24
    packets = []
    while offset + 16 <= len(data) and len(packets) < 200000:
        sec, usec, incl, orig = struct.unpack(endian + "IIII", data[offset:offset + 16])
        offset += 16
        if incl > snaplen or offset + incl > len(data):
            break
        packets.append((sec + usec / 1_000_000, data[offset:offset + incl]))
        offset += incl
    return network, snaplen, packets


def _pcapng(data: bytes) -> tuple[int, int, list[tuple[float, bytes]]]:
    if len(data) < 28 or data[:4] != b"\x0a\x0d\x0d\x0a":
        raise ValueError("Malformed PCAPNG section header")
    endian = "<" if data[8:12] == b"\x4d\x3c\x2b\x1a" else ">" if data[8:12] == b"\x1a\x2b\x3c\x4d" else None
    if endian is None:
        raise ValueError("Unsupported PCAPNG byte order")
    offset = 0
    interfaces = {}
    packets = []
    snaplen = 0
    while offset + 12 <= len(data) and len(packets) < 200000:
        btype, blen = struct.unpack(endian + "II", data[offset:offset + 8])
        if blen < 12 or offset + blen > len(data):
            break
        body = data[offset + 8:offset + blen - 4]
        if btype == 1 and len(body) >= 8:
            link, snap = struct.unpack(endian + "HHi", body[:8])
            interfaces[len(interfaces)] = (link, snap)
            snaplen = max(snaplen, snap)
        elif btype == 6 and len(body) >= 20:
            iface, hi, lo, caplen, orig = struct.unpack(endian + "IIIII", body[:20])
            raw = body[20:20 + caplen]
            ts = ((hi << 32) | lo) / 1_000_000
            packets.append((ts, raw))
        offset += blen
    link = interfaces.get(0, (1, snaplen))[0]
    return link, snaplen or 65535, packets


def _is_private(value: str | None) -> bool:
    return _ip_scope(value) == "private"


def _build_network_assessment(packet_records: list[dict], flows: dict, endpoints: Counter) -> dict:
    host_profiles = defaultdict(lambda: {
        "bytes_in": 0, "bytes_out": 0, "packets_in": 0, "packets_out": 0,
        "unique_peers": set(), "unique_external_peers": set(), "dest_ports": Counter(), "src_ports": Counter(),
        "dns_queries": set(), "http_hosts": set(), "tls_sni": set(), "evidence": [],
    })
    inbound = Counter()
    outbound = Counter()
    external_sources = Counter()
    internal_targets = Counter()
    for p in packet_records:
        src, dst = p.get("src"), p.get("dst")
        if not src or not dst:
            continue
        length = p.get("length", 0)
        if _is_private(src):
            hp = host_profiles[src]
            hp["bytes_out"] += length; hp["packets_out"] += 1; hp["unique_peers"].add(dst)
            if _ip_scope(dst) == "public": hp["unique_external_peers"].add(dst); outbound[src] += 1
            if p.get("dport"): hp["dest_ports"][p["dport"]] += 1
            if p.get("dns"):
                for q in p["dns"].get("questions", []):
                    if q.get("name"): hp["dns_queries"].add(q["name"])
            if (p.get("http") or {}).get("host"): hp["http_hosts"].add(p["http"]["host"])
            if p.get("tls_sni"): hp["tls_sni"].add(p["tls_sni"])
        if _is_private(dst):
            hp = host_profiles[dst]
            hp["bytes_in"] += length; hp["packets_in"] += 1; hp["unique_peers"].add(src)
            if _ip_scope(src) == "public": inbound[dst] += 1; external_sources[src] += 1; internal_targets[dst] += 1
            if p.get("sport"): hp["src_ports"][p["sport"]] += 1
    c2 = []
    for key, f in flows.items():
        src, dst, sport, dport, proto = key
        if not src or not dst or not _is_private(src) or _ip_scope(dst) != "public":
            continue
        timestamps = f.get("timestamps", [])
        intervals = [b - a for a, b in zip(timestamps, timestamps[1:]) if 0 < b - a <= 86400]
        regularity = 0.0
        if len(intervals) >= 3:
            avg = sum(intervals) / len(intervals)
            mad = sum(abs(x - avg) for x in intervals) / len(intervals)
            regularity = max(0.0, 1.0 - min(1.0, mad / max(avg, 1e-6)))
        score = 0
        reasons = []
        count = f.get("packets", 0)
        if count >= 4: score += 15; reasons.append("repeated outbound flow")
        if regularity >= 0.7: score += 30; reasons.append("periodic timing pattern")
        if dport in {80, 443, 8080, 8443}: score += 5; reasons.append("web destination")
        elif dport in {4444, 5555, 1337, 31337, 9001}: score += 30; reasons.append("commonly abused remote-control port")
        elif dport and dport not in {53, 123, 25, 110, 143, 587}: score += 12; reasons.append("non-standard outbound service port")
        if f.get("tls_sni"): reasons.append("TLS SNI observed")
        if f.get("http_hosts"): reasons.append("HTTP host observed")
        if score >= 30:
            c2.append({"internal_host": src, "destination": dst, "destination_port": dport, "protocol": proto, "packets": count, "bytes": f.get("bytes", 0), "regularity": round(regularity, 3), "score": min(score, 100), "reasons": reasons, "assessment": "potential_c2_candidate"})
    c2.sort(key=lambda x: (-x["score"], -x["packets"]))

    compromised = []
    for host, hp in host_profiles.items():
        score = 0; reasons = []
        if hp["unique_external_peers"]:
            score += 20; reasons.append(f"outbound connections to {len(hp['unique_external_peers'])} public peers")
        if outbound[host] >= 5:
            score += 15; reasons.append("repeated outbound activity")
        candidate_hits = [x for x in c2 if x["internal_host"] == host]
        if candidate_hits:
            score += min(50, max(x["score"] for x in candidate_hits)); reasons.append("potential command-and-control flow")
        if inbound[host] and any(p.get("dport") in {22, 23, 135, 139, 445, 3389, 5985} and p.get("dst") == host for p in packet_records):
            score += 20; reasons.append("inbound activity on administration/exposure ports")
        if score >= 35:
            compromised.append({"host": host, "score": min(score, 100), "confidence": "low" if score < 55 else "medium" if score < 75 else "high", "reasons": reasons, "potential_c2": candidate_hits[:10]})
    compromised.sort(key=lambda x: (-x["score"], x["host"]))

    attacker = []
    for src, count in external_sources.items():
        if count >= 2:
            targets = sorted({p.get("dst") for p in packet_records if p.get("src") == src and _is_private(p.get("dst")) and p.get("dst")})
            attacker.append({"source": src, "connections_to_internal": count, "internal_targets": targets[:50], "assessment": "external_attacker_candidate"})
    attacker.sort(key=lambda x: -x["connections_to_internal"])

    hosts = []
    for host, hp in host_profiles.items():
        hosts.append({"host": host, "bytes_in": hp["bytes_in"], "bytes_out": hp["bytes_out"], "packets_in": hp["packets_in"], "packets_out": hp["packets_out"], "unique_peers": len(hp["unique_peers"]), "unique_external_peers": sorted(hp["unique_external_peers"])[:100], "destination_ports": dict(hp["dest_ports"].most_common(30)), "dns_queries": sorted(hp["dns_queries"])[:100], "http_hosts": sorted(hp["http_hosts"])[:100], "tls_sni": sorted(hp["tls_sni"])[:100]})
    hosts.sort(key=lambda x: -(x["bytes_in"] + x["bytes_out"]))
    return {
        "internal_host_profiles": hosts[:200],
        "potential_compromised_hosts": compromised[:50],
        "potential_c2_candidates": c2[:100],
        "external_attacker_candidates": attacker[:100],
        "assessment_note": "These are passive heuristic candidates, not proof that a host was compromised or that an endpoint is C2. Validate with endpoint, identity and packet-level evidence.",
    }


def analyze_pcap(data: bytes) -> dict:
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        network, snaplen, raw_packets = _pcapng(data); fmt = "pcapng"
    else:
        network, snaplen, raw_packets = _classic_pcap(data); fmt = "pcap"
    protocols = Counter(); endpoints = Counter(); flows = defaultdict(lambda: {"packets": 0, "bytes": 0, "timestamps": [], "tls_sni": set(), "http_hosts": set()})
    dns = []; ioc_text = []; packets = []; findings = []; packet_records = []
    first_ts = last_ts = None
    interesting_ports = {21, 23, 25, 53, 110, 135, 139, 143, 389, 445, 1433, 3306, 3389, 4444, 5555, 5985, 8080, 8443}
    for ts, payload in raw_packets:
        first_ts = ts if first_ts is None else min(first_ts, ts); last_ts = ts if last_ts is None else max(last_ts, ts)
        f = _packet_fields(payload); protocols[f["protocol"]] += 1
        for endpoint in (f.get("src"), f.get("dst")):
            if endpoint: endpoints[endpoint] += len(payload)
        key = (f.get("src"), f.get("dst"), f.get("sport"), f.get("dport"), f.get("protocol"))
        flows[key]["packets"] += 1; flows[key]["bytes"] += len(payload); flows[key]["timestamps"].append(ts)
        if f.get("tls_sni"): flows[key]["tls_sni"].add(f["tls_sni"])
        if (f.get("http") or {}).get("host"): flows[key]["http_hosts"].add(f["http"]["host"])
        if f.get("dns"):
            dns.append({"timestamp": datetime.fromtimestamp(ts, timezone.utc).isoformat(), "src": f.get("src"), "dst": f.get("dst"), **f["dns"]})
        ioc_text.append(payload[:2_000_000].decode("latin1", "ignore"))
        if f.get("dport") in interesting_ports:
            findings.append({"type": "interesting-destination-port", "destination": f.get("dst"), "port": f.get("dport"), "protocol": f.get("protocol"), "timestamp": datetime.fromtimestamp(ts, timezone.utc).isoformat()})
        if f.get("src") and f.get("dst") and _ip_scope(f.get("src")) == "public" and _is_private(f.get("dst")):
            if f.get("dport") in {22, 23, 135, 139, 445, 3389, 5985}:
                findings.append({"type": "external-to-internal-admin-port", "source": f.get("src"), "destination": f.get("dst"), "port": f.get("dport"), "protocol": f.get("protocol"), "timestamp": datetime.fromtimestamp(ts, timezone.utc).isoformat()})
        record = {"timestamp": datetime.fromtimestamp(ts, timezone.utc).isoformat(), "length": len(payload), **{k: v for k, v in f.items() if k not in {"payload_iocs"}}}
        packet_records.append(record)
        if len(packets) < 5000:
            packets.append(record)
    iocs = extract_iocs("\n".join(ioc_text))
    duration = round(max(0.0, (last_ts or 0) - (first_ts or 0)), 6) if first_ts is not None else 0.0
    serial_flows = []
    for k, v in list(flows.items())[:5000]:
        serial_flows.append({"src": k[0], "dst": k[1], "sport": k[2], "dport": k[3], "protocol": k[4], "packets": v["packets"], "bytes": v["bytes"], "first_seen": datetime.fromtimestamp(min(v["timestamps"]), timezone.utc).isoformat() if v["timestamps"] else None, "last_seen": datetime.fromtimestamp(max(v["timestamps"]), timezone.utc).isoformat() if v["timestamps"] else None, "tls_sni": sorted(v["tls_sni"]), "http_hosts": sorted(v["http_hosts"])})
    assessment = _build_network_assessment(packet_records, flows, endpoints)
    return {
        "format": fmt, "link_type": network, "snaplen": snaplen, "packet_count": len(raw_packets), "total_bytes": sum(len(p) for _, p in raw_packets), "duration_seconds": duration,
        "protocols": dict(protocols.most_common()), "endpoints": [{"ip": ip, "scope": _ip_scope(ip), "bytes": n} for ip, n in endpoints.most_common(200)],
        "flows": serial_flows, "dns": dns[:5000], "findings": findings[:1000], "iocs": iocs, "sample_packets": packets,
        "network_assessment": assessment,
        "analysis_engine": {"name": "K4 Network Forensics Engine", "version": "10.2", "payload_execution": False, "capabilities": ["PCAP/PCAPNG parsing", "IPv4/IPv6", "DNS", "HTTP metadata", "TLS SNI", "flow analysis", "host profiling", "passive C2 heuristics", "external attacker heuristics"]},
        "analysis_note": "Passive packet parsing only. Potentially compromised hosts and C2 candidates are heuristic observations requiring independent validation; no payload execution, exploit delivery, or active scanning is performed.",
    }
