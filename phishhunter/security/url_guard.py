from __future__ import annotations

import ipaddress
import socket
from urllib.parse import unquote, urlparse

BLOCKED_HOSTS = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
    "metadata.azure.internal",
    "instance-data.ec2.internal",
}


def _blocked_ip(value: str) -> bool:
    ip = ipaddress.ip_address(value)
    blocked_networks = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("100.64.0.0/10"),
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("fc00::/7"),
        ipaddress.ip_network("fe80::/10"),
        ipaddress.ip_network("::ffff:127.0.0.0/104"),
    ]
    return any(
        [ip.is_loopback, ip.is_private, ip.is_link_local, ip.is_multicast, ip.is_reserved, ip.is_unspecified]
    ) or any(ip in network for network in blocked_networks)


def resolve_and_validate(host: str, port: int) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError(f"DNS resolution failed: {exc}") from exc
    addresses = sorted({info[4][0] for info in infos})
    for address in addresses:
        try:
            if _blocked_ip(address):
                raise ValueError(f"Resolved destination is blocked: {address}")
        except ValueError:
            raise
    if not addresses:
        raise ValueError("DNS returned no usable addresses")
    return addresses


def validate_url(url: str) -> str:
    value = url.strip()
    if len(value) > 2048:
        raise ValueError("URL is too long")
    parsed = urlparse(value)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Only http and https URLs are accepted")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded credentials are not accepted")
    host = parsed.hostname.rstrip(".").lower()
    try:
        host_ascii = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Invalid internationalized hostname") from exc
    if host_ascii in BLOCKED_HOSTS:
        raise ValueError("Destination is blocked")
    if host_ascii in {"0.0.0.0", "::"}:
        raise ValueError("Unspecified destination is blocked")
    try:
        if _blocked_ip(host_ascii):
            raise ValueError("Destination address is blocked")
        return value
    except ValueError as exc:
        if str(exc) == "Destination address is blocked":
            raise
    resolve_and_validate(host_ascii, parsed.port or (443 if parsed.scheme.lower() == "https" else 80))
    return value


def url_features(url: str) -> dict:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    decoded_path = unquote(parsed.path or "")
    labels = host.split(".") if host else []
    suspicious_tld = labels[-1] in {"zip", "mov", "click", "top", "gq", "tk", "xyz"} if labels else False
    return {
        "scheme": parsed.scheme.lower(),
        "hostname": host.lower(),
        "port": parsed.port,
        "subdomain_count": max(0, len(labels) - 2),
        "hostname_is_ip": _is_ip(host),
        "punycode": "xn--" in host.lower(),
        "at_symbol": "@" in url,
        "encoded_path": decoded_path != parsed.path,
        "query_length": len(parsed.query),
        "fragment_present": bool(parsed.fragment),
        "path_length": len(parsed.path),
        "suspicious_tld": suspicious_tld,
        "dash_in_hostname": "-" in host,
        "digit_in_hostname": any(ch.isdigit() for ch in host),
        "label_lengths": [len(label) for label in labels],
    }


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False
