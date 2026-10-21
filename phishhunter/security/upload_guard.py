from __future__ import annotations

from pathlib import Path, PurePosixPath
import re
from typing import BinaryIO

MAGIC = {
    ".exe": (b"MZ",),
    ".dll": (b"MZ",),
    ".sys": (b"MZ",),
    ".scr": (b"MZ",),
    ".cpl": (b"MZ",),
    ".pdf": (b"%PDF",),
    ".zip": (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"),
    ".jar": (b"PK\x03\x04",),
    ".apk": (b"PK\x03\x04",),
    ".docx": (b"PK\x03\x04",),
    ".xlsx": (b"PK\x03\x04",),
    ".pptx": (b"PK\x03\x04",),
    ".png": (b"\x89PNG\r\n\x1a\n",),
    ".jpg": (b"\xff\xd8\xff",),
    ".jpeg": (b"\xff\xd8\xff",),
    ".gif": (b"GIF87a", b"GIF89a"),
}

CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def sanitize_filename(filename: str) -> str:
    if not filename or len(filename) > 255:
        raise ValueError("Invalid filename")
    if "\x00" in filename:
        raise ValueError("Filename contains a NUL byte")
    if CONTROL_RE.search(filename):
        raise ValueError("Filename contains control characters")
    normalized = filename.replace("\\", "/")
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:/", normalized):
        raise ValueError("Absolute paths are not allowed")
    parts = PurePosixPath(normalized).parts
    if any(part == ".." for part in parts):
        raise ValueError("Path traversal is not allowed")
    cleaned = PurePosixPath(normalized).name
    if cleaned in {"", ".", ".."}:
        raise ValueError("Invalid filename")
    return cleaned


def validate_upload(filename: str, data: bytes, max_mb: int) -> str:
    safe_name = sanitize_filename(filename)
    max_bytes = max(1, int(max_mb)) * 1024 * 1024
    if len(data) == 0:
        raise ValueError("Empty uploads are not accepted")
    if len(data) > max_bytes:
        raise ValueError(f"File exceeds {max_mb} MB limit")
    suffix = Path(safe_name).suffix.lower()
    expected = MAGIC.get(suffix)
    if expected and not any(data.startswith(prefix) for prefix in expected):
        raise ValueError("File signature does not match the extension")
    return safe_name


async def read_upload_limited(upload: BinaryIO, max_bytes: int, chunk_size: int = 1024 * 1024) -> bytes:
    """Read an UploadFile-like object without allowing an unbounded request body in RAM."""
    chunks: list[bytes] = []
    total = 0
    limit = max(1, int(max_bytes))
    while True:
        chunk = await upload.read(chunk_size)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise ValueError(f"Upload exceeds {limit // (1024 * 1024)} MB limit")
        chunks.append(chunk)
    return b"".join(chunks)
