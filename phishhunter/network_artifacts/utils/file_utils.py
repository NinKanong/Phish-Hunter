from __future__ import annotations
import base64, binascii, math, mimetypes, re, struct, zipfile, tarfile, io
from collections import Counter
from pathlib import PurePosixPath
from typing import Any
from .hash_utils import hash_bytes

MAGIC = [
    (b"MZ", "PE/Windows executable", "application/vnd.microsoft.portable-executable"),
    (b"\x7fELF", "ELF executable", "application/x-elf"),
    (b"PK\x03\x04", "ZIP/Office/JAR archive", "application/zip"),
    (b"\x89PNG\r\n\x1a\n", "PNG image", "image/png"),
    (b"\xff\xd8\xff", "JPEG image", "image/jpeg"),
    (b"GIF89a", "GIF image", "image/gif"),
    (b"GIF87a", "GIF image", "image/gif"),
    (b"%PDF-", "PDF document", "application/pdf"),
    (b"\x1f\x8b\x08", "GZIP archive", "application/gzip"),
    (b"Rar!\x1a\x07", "RAR archive", "application/vnd.rar"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive", "application/x-7z-compressed"),
    (b"SQLite format 3\x00", "SQLite database", "application/vnd.sqlite3"),
]

SUSPICIOUS_EXT = {".exe", ".dll", ".sys", ".scr", ".ps1", ".vbs", ".js", ".hta", ".lnk", ".bat", ".cmd", ".msi", ".jar", ".apk", ".elf"}


def entropy(data: bytes) -> float:
    if not data: return 0.0
    counts = Counter(data); n = len(data)
    return round(-sum((c/n)*math.log2(c/n) for c in counts.values()), 5)


def detect_type(data: bytes, filename: str = "") -> tuple[str, str, str]:
    lower = filename.lower()
    for magic, label, mime in MAGIC:
        if data.startswith(magic):
            return label, mime, "magic"
    mime, _ = mimetypes.guess_type(filename)
    if data[:1024].lstrip().startswith((b"{", b"[")):
        return "JSON/text", mime or "application/json", "content"
    if b"<!doctype html" in data[:4096].lower() or b"<html" in data[:4096].lower():
        return "HTML document", "text/html", "content"
    if mime:
        return "Filename-derived type", mime, "extension"
    return "Unknown binary", "application/octet-stream", "fallback"


def strings(data: bytes, minimum: int = 6, limit: int = 500) -> list[str]:
    pattern = re.compile(rb"[ -~]{%d,}" % minimum)
    out=[]
    for match in pattern.finditer(data[:5_000_000]):
        try: out.append(match.group().decode("ascii", "ignore")[:1000])
        except Exception: pass
        if len(out)>=limit: break
    return out


def static_profile(data: bytes, filename: str = "") -> dict[str, Any]:
    kind, mime, source = detect_type(data, filename)
    ext = PurePosixPath(filename).suffix.lower()
    text = data[:2_000_000].decode("utf-8", "replace")
    lower = text.lower()
    indicators = {
        "urls": sorted(set(re.findall(r"https?://[^\s\"'<>]{3,500}", text, re.I)))[:200],
        "domains": sorted(set(re.findall(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", text, re.I)))[:500],
        "ips": sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)))[:200],
        "emails": sorted(set(re.findall(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", text)))[:100],
    }
    suspicious_keywords=[x for x in ["powershell", "cmd.exe", "rundll32", "regsvr32", "mshta", "certutil", "bitsadmin", "wscript", "cscript", "schtasks", "downloadstring", "invoke-expression", "base64"] if x in lower]
    return {
        "filename": filename, "size": len(data), "type": kind, "mime": mime, "type_source": source,
        "extension": ext, "entropy": entropy(data), "hashes": hash_bytes(data),
        "sha256": hash_bytes(data)["sha256"], "is_empty": not bool(data),
        "suspicious_extension": ext in SUSPICIOUS_EXT,
        "suspicious_keywords": suspicious_keywords,
        "strings_count": len(strings(data)), "strings_sample": strings(data, limit=100),
        "indicators": indicators,
    }


def archive_listing(data: bytes, filename: str) -> dict[str, Any]:
    out={"supported": False,"entries":[],"errors":[]}
    bio=io.BytesIO(data)
    try:
        if data.startswith(b"PK\x03\x04"):
            with zipfile.ZipFile(bio) as z:
                out["supported"]=True
                for info in z.infolist()[:500]:
                    out["entries"].append({"name":info.filename,"size":info.file_size,"compressed":info.compress_size,"crc32":format(info.CRC,'08x'),"encrypted":bool(info.flag_bits & 1)})
        elif data.startswith(b"\x1f\x8b\x08"):
            with tarfile.open(fileobj=io.BytesIO(__import__('gzip').decompress(data)) if data else bio, mode="r:*") as t:
                out["supported"]=True
                for info in t.getmembers()[:500]: out["entries"].append({"name":info.name,"size":info.size,"type":info.type})
    except Exception as exc:
        out["errors"].append(str(exc))
    return out
