from __future__ import annotations

import http.client
import socket
import ssl
from urllib.parse import urljoin, urlparse

from phishhunter.config import settings
from phishhunter.security.url_guard import resolve_and_validate, validate_url

MAX_BODY = 2 * 1024 * 1024
REDIRECT_STATUS = {301, 302, 303, 307, 308}


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, connect_ip: str, timeout: float):
        super().__init__(host, port, timeout=timeout)
        self._connect_ip = connect_ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._connect_ip, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, connect_ip: str, timeout: float, context: ssl.SSLContext):
        super().__init__(host, port, timeout=timeout, context=context)
        self._connect_ip = connect_ip

    def connect(self) -> None:
        raw = socket.create_connection((self._connect_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


def _normalized_host(host: str) -> str:
    try:
        return host.rstrip(".").encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Invalid internationalized hostname") from exc


def _fetch_once(url: str, connect_ip: str) -> dict:
    parsed = urlparse(url)
    host = _normalized_host(parsed.hostname or "")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    headers = {
        "Host": f"{host}:{port}" if (parsed.scheme == "http" and port != 80) or (parsed.scheme == "https" and port != 443) else host,
        "User-Agent": "Phish-Hunter/18.0 URL-Domain-Analyst",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,text/plain;q=0.8,*/*;q=0.5",
        "Accept-Encoding": "identity",
        "Connection": "close",
    }
    timeout = max(1, settings.fetch_timeout_seconds)
    if parsed.scheme == "https":
        context = ssl.create_default_context()
        connection = _PinnedHTTPSConnection(host, port, connect_ip, timeout, context)
    else:
        connection = _PinnedHTTPConnection(host, port, connect_ip, timeout)
    try:
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        body = response.read(MAX_BODY + 1)
        truncated = len(body) > MAX_BODY
        body = body[:MAX_BODY]
        charset = "utf-8"
        content_type = response.getheader("Content-Type", "") or ""
        match = None
        for part in content_type.split(";"):
            if "charset=" in part.lower():
                match = part.split("=", 1)[1].strip().strip('"')
                break
        if match:
            charset = match
        return {
            "status_code": int(response.status),
            "reason": response.reason,
            "final_url": url,
            "headers": {key.lower(): value for key, value in response.getheaders()},
            "content": body.decode(charset, errors="replace"),
            "content_length": len(body),
            "truncated": truncated,
            "resolved_ip": connect_ip,
        }
    finally:
        connection.close()


async def fetch_url(url: str) -> dict:
    """Fetch a URL using an IP selected from a freshly SSRF-checked DNS result.

    HTTP redirects are handled manually. Every redirect URL is validated and resolved
    again before the next connection, and the socket connects to that checked IP rather
    than asking the OS to resolve the hostname again.
    """
    current = validate_url(url)
    redirects: list[str] = []
    resolutions: list[dict] = []
    for _ in range(settings.max_redirects + 1):
        current = validate_url(current)
        parsed = urlparse(current)
        addresses = resolve_and_validate(
            _normalized_host(parsed.hostname or ""),
            parsed.port or (443 if parsed.scheme == "https" else 80),
        )
        connect_ip = addresses[0]
        resolutions.append({"url": current, "addresses": addresses, "selected": connect_ip})
        result = _fetch_once(current, connect_ip)
        location = result["headers"].get("location")
        if result["status_code"] in REDIRECT_STATUS and location:
            next_url = urljoin(current, location)
            validate_url(next_url)
            redirects.append(next_url)
            current = next_url
            continue
        result["history"] = redirects
        result["redirect_count"] = len(redirects)
        result["resolutions"] = resolutions
        return result
    raise ValueError("Maximum redirect count exceeded")
