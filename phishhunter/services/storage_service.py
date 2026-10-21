from __future__ import annotations
from pathlib import Path
import hashlib
import secrets
from phishhunter.config import settings

class StorageService:
    """Local durable object storage with an S3-compatible interface boundary.
    Production deployments can replace this adapter with MinIO/S3 without changing routes.
    """
    def __init__(self): self.root = Path(settings.storage_dir).resolve() / "objects"
    def put(self, tenant_id: int | None, job_id: str, filename: str, data: bytes) -> tuple[str, str]:
        safe = Path(filename).name or "artifact.bin"
        digest = hashlib.sha256(data).hexdigest()
        key = f"{tenant_id or 'guest'}/{job_id}/{secrets.token_hex(6)}-{safe}"
        path = self.root / key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return key, str(path)
    def get(self, key: str) -> bytes:
        path = self.root / key
        if not path.resolve().is_relative_to(self.root): raise ValueError("Invalid storage key")
        return path.read_bytes()

storage_service = StorageService()
