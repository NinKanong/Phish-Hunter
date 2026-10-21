from collections import defaultdict, deque
from threading import Lock
from time import monotonic

from fastapi import HTTPException, Request

from phishhunter.config import settings

_BUCKETS: dict[str, deque[float]] = defaultdict(deque)
_LOCK = Lock()


def _client_key(request: Request, bucket: str) -> str:
    client_ip = request.client.host if request.client else "unknown"
    if settings.trusted_proxy_count > 0:
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            parts = [item.strip() for item in forwarded.split(",") if item.strip()]
            if parts:
                # When behind a known proxy chain, take the left-most original client.
                client_ip = parts[0]
    return f"{bucket}:{client_ip}"


def enforce_rate_limit(request: Request) -> None:
    path = request.url.path
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return
    bucket = "general"
    limit = settings.rate_limit_max_requests
    if path.startswith("/login") or path.startswith("/register"):
        bucket, limit = "auth", settings.auth_rate_limit_max_requests
    elif path.startswith("/analyze/") or path.startswith("/api/v1/url"):
        bucket, limit = "analysis", settings.analysis_rate_limit_max_requests

    now = monotonic()
    key = _client_key(request, bucket)
    with _LOCK:
        timestamps = _BUCKETS[key]
        cutoff = now - settings.rate_limit_window_seconds
        while timestamps and timestamps[0] <= cutoff:
            timestamps.popleft()
        if len(timestamps) >= limit:
            raise HTTPException(status_code=429, detail="Rate limit exceeded")
        timestamps.append(now)

    request.state.rate_limit = {"bucket": bucket, "limit": limit}
