from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from phishhunter.config import settings


@dataclass(frozen=True)
class SandboxResult:
    status: str
    backend: str
    evidence: dict


class SandboxManager:
    """Safety boundary for an external detonation service.

    This application never launches samples locally. A real sandbox must run as a
    separately isolated VM/microVM service with its own storage and network controls.
    """

    def submit(self, artifact_sha256: str) -> SandboxResult:
        if not settings.sandbox_enabled or settings.sandbox_backend.lower() == "disabled":
            return SandboxResult(
                "disabled",
                settings.sandbox_backend,
                {"message": "Dynamic execution is disabled. Configure a dedicated isolated sandbox service."},
            )
        if not artifact_sha256 or len(artifact_sha256) != 64:
            return SandboxResult("rejected", settings.sandbox_backend, {"message": "A SHA-256 artifact identifier is required."})
        parsed = urlparse(settings.sandbox_endpoint)
        if parsed.scheme != "https" or not parsed.netloc:
            return SandboxResult(
                "misconfigured",
                settings.sandbox_backend,
                {"message": "SANDBOX_ENDPOINT must be an HTTPS endpoint on the dedicated sandbox host."},
            )
        return SandboxResult(
            "queued",
            settings.sandbox_backend,
            {
                "artifact_sha256": artifact_sha256,
                "endpoint": settings.sandbox_endpoint,
                "execution_host": "external-isolated-sandbox",
                "host_execution": False,
            },
        )
