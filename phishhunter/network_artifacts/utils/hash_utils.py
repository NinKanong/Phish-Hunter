from __future__ import annotations
from hashlib import md5, sha1, sha256, sha512
from pathlib import Path
from typing import BinaryIO

CHUNK = 1024 * 1024

def hash_bytes(data: bytes) -> dict[str, str]:
    return {
        "md5": md5(data, usedforsecurity=False).hexdigest(),
        "sha1": sha1(data, usedforsecurity=False).hexdigest(),
        "sha256": sha256(data).hexdigest(),
        "sha512": sha512(data).hexdigest(),
    }

def hash_file(handle: BinaryIO) -> dict[str, str]:
    h = [md5(usedforsecurity=False), sha1(usedforsecurity=False), sha256(), sha512()]
    while True:
        chunk = handle.read(CHUNK)
        if not chunk:
            break
        for item in h:
            item.update(chunk)
    return {"md5": h[0].hexdigest(), "sha1": h[1].hexdigest(), "sha256": h[2].hexdigest(), "sha512": h[3].hexdigest()}
