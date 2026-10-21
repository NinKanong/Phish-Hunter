from __future__ import annotations

import io
import json
import mimetypes
from datetime import datetime, timezone
from pathlib import Path
import re
import struct
import zipfile

from phishhunter_common.hash import hash_bytes
from phishhunter_common.ioc import extract_iocs
from phishhunter.analysis.correlation import correlate_evidence
from phishhunter.utils.analysis import behavior_findings, entropy, strings_from_bytes
from phishhunter.mitre import attribution_guardrail


PACKER_MARKERS = {
    "UPX": [b"UPX0", b"UPX1", b"UPX2"],
    "Themida": [b"Themida", b"WinLicense"],
    "VMProtect": [b"VMProtect", b"VMP0", b"VMP1"],
    "ASPack": [b"ASPack", b".aspack"],
}

SCRIPT_EXTENSIONS = {
    ".ps1": "PowerShell",
    ".psm1": "PowerShell module",
    ".bat": "Windows batch",
    ".cmd": "Windows command shell",
    ".vbs": "VBScript",
    ".vbe": "Encoded VBScript",
    ".js": "JavaScript",
    ".jse": "Encoded JavaScript",
    ".hta": "HTA",
    ".wsf": "Windows Script File",
    ".sh": "Shell script",
    ".py": "Python",
    ".pl": "Perl",
    ".php": "PHP",
}


SUSPICIOUS_IMPORTS = {
    "VirtualAlloc": ("memory-allocation", "T1106", "high"),
    "VirtualProtect": ("memory-permission-change", "T1106", "medium"),
    "WriteProcessMemory": ("remote-memory-write", "T1055", "high"),
    "CreateRemoteThread": ("remote-thread-creation", "T1055", "high"),
    "NtCreateThreadEx": ("native-thread-creation", "T1055", "high"),
    "WinExec": ("native-process-launch", "T1106", "medium"),
    "CreateProcess": ("process-creation", "T1106", "medium"),
    "ShellExecute": ("shell-execution", "T1204", "medium"),
    "URLDownloadToFile": ("download-to-file", "T1105", "high"),
    "InternetOpenUrl": ("network-access", "T1071.001", "medium"),
    "WinHttpOpenRequest": ("network-access", "T1071.001", "medium"),
    "CryptUnprotectData": ("credential-data-access", "T1555", "high"),
    "IsDebuggerPresent": ("debugger-detection", "T1497", "medium"),
    "CheckRemoteDebuggerPresent": ("debugger-detection", "T1497", "medium"),
    "GetTickCount": ("timing-check", "T1497", "low"),
}

EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".sys", ".scr", ".cpl", ".com", ".msi", ".jar", ".hta", ".ps1", ".js", ".vbs", ".cmd", ".bat"}


def name_metadata(filename: str, filekind: str) -> dict:
    lower = Path(filename).name.lower()
    suffixes = [item.lower() for item in Path(filename).suffixes]
    double_extension = len(suffixes) >= 2 and suffixes[-1] in EXECUTABLE_EXTENSIONS
    suspicious_name_words = [word for word in ("invoice", "payment", "resume", "document", "scan", "update", "urgent", "password") if word in lower]
    magic_kind = filekind.lower()
    executable_content = any(token in magic_kind for token in ("pe/windows", "elf", "mach-o"))
    return {
        "basename": Path(filename).name,
        "suffix": Path(filename).suffix.lower(),
        "suffixes": suffixes,
        "double_extension": double_extension,
        "executable_extension": Path(filename).suffix.lower() in EXECUTABLE_EXTENSIONS,
        "content_looks_executable": executable_content,
        "extension_content_mismatch": executable_content and Path(filename).suffix.lower() not in EXECUTABLE_EXTENSIONS,
        "suspicious_name_words": suspicious_name_words,
    }


def byte_profile(data: bytes) -> dict:
    if not data:
        return {"size": 0, "null_ratio": 0.0, "printable_ratio": 0.0}
    window = data[:8_000_000]
    nulls = window.count(b"\x00")
    printable = sum(1 for byte in window if 32 <= byte <= 126 or byte in (9, 10, 13))
    return {
        "size": len(data),
        "analyzed_window": len(window),
        "null_ratio": round(nulls / len(window), 6),
        "printable_ratio": round(printable / len(window), 6),
        "entropy": round(entropy(window), 4),
    }


def pe_security_metadata(pe: dict) -> dict:
    if not pe.get("valid_pe"):
        return {}
    flags = int(str(pe.get("dll_characteristics", "0x0")), 16)
    return {
        "aslr": bool(flags & 0x0040),
        "dep_nx": bool(flags & 0x0100),
        "cfg": bool(flags & 0x4000),
        "high_entropy_va": bool(flags & 0x0020),
        "signed_table_present": bool(pe.get("import_directory", {}).get("certificate_table", {}).get("present")),
    }


def anti_analysis_metadata(data: bytes, strings: list[str]) -> dict:
    text = "\n".join(strings).lower()
    markers = {
        "debugger_checks": ["isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess"],
        "virtualization_markers": ["vmware", "vbox", "virtualbox", "hyper-v", "qemu", "sandboxie"],
        "timing_markers": ["gettickcount", "queryperformancecounter", "rdtsc", "sleep"],
        "analysis_environment_markers": ["wireshark", "procmon", "processhacker", "x64dbg", "ollydbg", "ida", "ghidra"],
    }
    found = {key: sorted({marker for marker in values if marker in text}) for key, values in markers.items()}
    return {"markers": found, "category_count": sum(bool(values) for values in found.values()), "raw_byte_markers_checked": True}


def imported_api_signals(pe: dict, strings: list[str] | None = None) -> list[dict]:
    observed = [str(value) for value in pe.get("import_directory", {}).get("functions", [])]
    observed.extend(str(value) for value in pe.get("imports_seen_in_strings", []))
    observed.extend(str(value) for value in (strings or []))
    corpus = "\n".join(observed).lower()
    signals = []
    for needle, (category, technique, severity) in SUSPICIOUS_IMPORTS.items():
        if needle.lower() in corpus:
            signals.append({"api": needle, "category": category, "technique": technique, "severity": severity})
    return signals


class Cursor:
    def __init__(self, data: bytes):
        self.data = data

    def u16(self, offset: int, endian: str = "<") -> int:
        if offset < 0 or offset + 2 > len(self.data):
            return 0
        return struct.unpack_from(endian + "H", self.data, offset)[0]

    def u32(self, offset: int, endian: str = "<") -> int:
        if offset < 0 or offset + 4 > len(self.data):
            return 0
        return struct.unpack_from(endian + "I", self.data, offset)[0]

    def u64(self, offset: int, endian: str = "<") -> int:
        if offset < 0 or offset + 8 > len(self.data):
            return 0
        return struct.unpack_from(endian + "Q", self.data, offset)[0]


def file_type(data: bytes, filename: str) -> str:
    if data.startswith(b"MZ"):
        return "PE/Windows executable"
    if data.startswith(b"%PDF"):
        return "PDF"
    if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06"):
        return "ZIP/container"
    if data.startswith(b"\x7fELF"):
        return "ELF"
    if data[:4] in {
        b"\xfe\xed\xfa\xce",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
        b"\xbe\xba\xfe\xca",
        b"\xca\xfe\xba\xbf",
        b"\xbf\xba\xfe\xca",
    }:
        return "Mach-O"
    if data.startswith(b"SQLite format 3\x00"):
        return "SQLite database"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "PNG"
    if data[:3] == b"\xff\xd8\xff":
        return "JPEG"
    if data[:6] in {b"GIF87a", b"GIF89a"}:
        return "GIF"
    ext = Path(filename).suffix.lower()
    return f"unknown ({ext or 'no extension'})"


def _timestamp(value: int) -> str | None:
    if not value:
        return None
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _read_c_string(data: bytes, offset: int, size: int = 96) -> str:
    if offset < 0 or offset >= len(data):
        return ""
    raw = data[offset : min(len(data), offset + size)]
    return raw.split(b"\x00", 1)[0].decode("ascii", errors="ignore")


def _rva_to_offset(rva: int, sections: list[dict]) -> int | None:
    for section in sections:
        start = int(section["virtual_address"], 16)
        raw_size = int(section["raw_size"])
        virtual_size = int(section["virtual_size"])
        span = max(raw_size, virtual_size)
        if start <= rva < start + span:
            offset = int(section["raw_pointer"], 16) + (rva - start)
            return offset
    return None


def _pe_imports(data: bytes, optional_offset: int, magic: int, sections: list[dict]) -> dict:
    directory_base = optional_offset + (112 if magic == 0x20B else 96)
    if directory_base + 16 > len(data):
        return {"present": False, "dlls": [], "functions": []}
    import_rva = int.from_bytes(data[directory_base + 8 : directory_base + 12], "little")
    import_size = int.from_bytes(data[directory_base + 12 : directory_base + 16], "little")
    certificate_rva = int.from_bytes(data[directory_base + 32 : directory_base + 36], "little") if directory_base + 36 <= len(data) else 0
    certificate_size = int.from_bytes(data[directory_base + 36 : directory_base + 40], "little") if directory_base + 40 <= len(data) else 0
    result = {
        "present": bool(import_rva),
        "directory_rva": hex(import_rva),
        "directory_size": import_size,
        "dlls": [],
        "functions": [],
        "certificate_table": {"present": bool(certificate_rva and certificate_size), "offset": certificate_rva, "size": certificate_size},
    }
    import_offset = _rva_to_offset(import_rva, sections) if import_rva else None
    if import_offset is None:
        return result
    pointer_size = 8 if magic == 0x20B else 4
    ordinal_flag = 1 << (63 if pointer_size == 8 else 31)
    seen = 0
    dll_seen: set[str] = set()
    function_seen: set[str] = set()
    while import_offset + 20 <= len(data) and seen < 512:
        oft = int.from_bytes(data[import_offset : import_offset + 4], "little")
        name_rva = int.from_bytes(data[import_offset + 12 : import_offset + 16], "little")
        ft = int.from_bytes(data[import_offset + 16 : import_offset + 20], "little")
        if not (oft or name_rva or ft):
            break
        name_offset = _rva_to_offset(name_rva, sections)
        dll = _read_c_string(data, name_offset or -1, 128).strip().lower()
        if dll and dll not in dll_seen:
            dll_seen.add(dll)
            result["dlls"].append(dll)
        thunk_rva = oft or ft
        thunk_offset = _rva_to_offset(thunk_rva, sections)
        if thunk_offset is not None:
            for index in range(512):
                off = thunk_offset + index * pointer_size
                if off + pointer_size > len(data):
                    break
                value = int.from_bytes(data[off : off + pointer_size], "little")
                if value == 0:
                    break
                if value & ordinal_flag:
                    func = f"ordinal:{value & 0xFFFF}"
                else:
                    hint_name_offset = _rva_to_offset(value, sections)
                    func = _read_c_string(data, (hint_name_offset or -2) + 2, 192) if hint_name_offset is not None else ""
                    func = func.strip()
                if func and func not in function_seen:
                    function_seen.add(func)
                    result["functions"].append(func)
        import_offset += 20
        seen += 1
    result["dlls"] = result["dlls"][:256]
    result["functions"] = result["functions"][:2000]
    result["certificate_table"]["offset"] = certificate_rva
    return result


def pe_metadata(data: bytes) -> dict:
    c = Cursor(data)
    if not data.startswith(b"MZ") or len(data) < 0x40:
        return {}
    pe_offset = c.u32(0x3C)
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        return {"valid_pe": False, "error": "PE signature not found"}

    machine = c.u16(pe_offset + 4)
    sections_count = c.u16(pe_offset + 6)
    timestamp = c.u32(pe_offset + 8)
    optional_size = c.u16(pe_offset + 20)
    optional_offset = pe_offset + 24
    magic = c.u16(optional_offset)
    is_pe32_plus = magic == 0x20B
    image_base = c.u64(optional_offset + 24) if is_pe32_plus else c.u32(optional_offset + 28)
    subsystem_offset = optional_offset + (68 if is_pe32_plus else 68)
    subsystem = c.u16(subsystem_offset)
    dll_characteristics = c.u16(optional_offset + (70 if is_pe32_plus else 70))
    entry_point = c.u32(optional_offset + 16)
    section_offset = optional_offset + optional_size
    sections = []
    for index in range(min(sections_count, 96)):
        off = section_offset + index * 40
        if off + 40 > len(data):
            break
        name = _read_c_string(data, off, 8) or f"section_{index}"
        virtual_size = c.u32(off + 8)
        virtual_address = c.u32(off + 12)
        raw_size = c.u32(off + 16)
        raw_pointer = c.u32(off + 20)
        characteristics = c.u32(off + 36)
        section_blob = data[raw_pointer : min(len(data), raw_pointer + raw_size)]
        sec_entropy = round(entropy(section_blob), 4) if section_blob else 0.0
        sections.append(
            {
                "name": name,
                "virtual_size": virtual_size,
                "virtual_address": hex(virtual_address),
                "raw_size": raw_size,
                "raw_pointer": hex(raw_pointer),
                "characteristics": hex(characteristics),
                "entropy": sec_entropy,
                "high_entropy": sec_entropy >= 7.2,
            }
        )

    imports = []
    export_markers = []
    string_blob = data.decode("latin-1", errors="ignore")
    for dll in re.findall(r"[A-Za-z0-9_ .-]{2,80}\.dll", string_blob, re.I):
        cleaned = dll.strip().lower()
        if cleaned not in imports:
            imports.append(cleaned)
    for marker in (
        b"kernel32.dll",
        b"advapi32.dll",
        b"ntdll.dll",
        b"user32.dll",
        b"wininet.dll",
        b"winhttp.dll",
        b"urlmon.dll",
        b"ws2_32.dll",
        b"crypt32.dll",
    ):
        if marker.lower() in data.lower():
            export_markers.append(marker.decode())

    return {
        "valid_pe": True,
        "machine": hex(machine),
        "sections_count": sections_count,
        "timestamp": timestamp,
        "timestamp_utc": _timestamp(timestamp),
        "optional_magic": hex(magic),
        "architecture": "x64" if is_pe32_plus else "x86" if magic == 0x10B else "unknown",
        "entry_point_rva": hex(entry_point),
        "image_base": hex(image_base),
        "subsystem": subsystem,
        "dll_characteristics": hex(dll_characteristics),
        "sections": sections,
        "imports_seen_in_strings": imports[:200],
        "common_api_dlls_seen": export_markers,
        "import_directory": _pe_imports(data, optional_offset, magic, sections),
        "overlay_size": _pe_overlay_size(data, sections),
    }


def _pe_overlay_size(data: bytes, sections: list[dict]) -> int:
    max_raw_end = 0
    for section in sections:
        max_raw_end = max(max_raw_end, int(section["raw_pointer"], 16) + int(section["raw_size"]))
    return max(0, len(data) - max_raw_end)


def elf_metadata(data: bytes) -> dict:
    if not data.startswith(b"\x7fELF") or len(data) < 64:
        return {}
    elf_class = data[4]
    data_encoding = data[5]
    endian = "<" if data_encoding == 1 else ">" if data_encoding == 2 else "<"
    c = Cursor(data)
    machine = c.u16(18, endian)
    entry = c.u64(24, endian) if elf_class == 2 else c.u32(24, endian)
    phoff = c.u64(32, endian) if elf_class == 2 else c.u32(28, endian)
    shoff = c.u64(40, endian) if elf_class == 2 else c.u32(32, endian)
    return {
        "class": "ELF64" if elf_class == 2 else "ELF32" if elf_class == 1 else "unknown",
        "endianness": "little" if data_encoding == 1 else "big" if data_encoding == 2 else "unknown",
        "machine": hex(machine),
        "entry_point": hex(entry),
        "program_header_offset": phoff,
        "section_header_offset": shoff,
    }


def macho_metadata(data: bytes) -> dict:
    if len(data) < 8:
        return {}
    magic_bytes = data[:4]
    known = {
        b"\xfe\xed\xfa\xce": ("32-bit Mach-O", "big"),
        b"\xce\xfa\xed\xfe": ("32-bit Mach-O (little endian)", "little"),
        b"\xfe\xed\xfa\xcf": ("64-bit Mach-O", "big"),
        b"\xcf\xfa\xed\xfe": ("64-bit Mach-O (little endian)", "little"),
        b"\xca\xfe\xba\xbe": ("Mach-O universal binary", "big"),
        b"\xbe\xba\xfe\xca": ("Mach-O universal binary (little endian)", "little"),
        b"\xca\xfe\xba\xbf": ("Mach-O universal binary 64", "big"),
        b"\xbf\xba\xfe\xca": ("Mach-O universal binary 64 (little endian)", "little"),
    }
    if magic_bytes not in known:
        return {}
    format_name, endian_name = known[magic_bytes]
    cpu = int.from_bytes(data[4:8], endian_name)
    return {
        "magic": "0x" + magic_bytes.hex(),
        "format": format_name,
        "endianness": endian_name,
        "cpu_type": hex(cpu),
    }

def pdf_metadata(data: bytes) -> dict:
    if not data.startswith(b"%PDF"):
        return {}
    text = data[: min(len(data), 8_000_000)].decode("latin-1", errors="ignore")
    indicators = {
        name: len(re.findall(pattern, text, re.I))
        for name, pattern in {
            "javascript": r"/JavaScript|/JS\b",
            "open_action": r"/OpenAction\b",
            "additional_actions": r"/AA\b",
            "launch": r"/Launch\b",
            "embedded_file": r"/EmbeddedFile\b",
            "uri_action": r"/URI\b",
            "acroform": r"/AcroForm\b",
            "object_stream": r"/ObjStm\b",
            "rich_media": r"/RichMedia\b",
            "xref_stream": r"/XRef\b",
        }.items()
    }
    return {"version": _pdf_version(data), "indicators": indicators, "suspicious": any(indicators.values())}


def _pdf_version(data: bytes) -> str:
    match = re.match(br"%PDF-(\d\.\d)", data[:16])
    return match.group(1).decode() if match else "unknown"


def archive_metadata(data: bytes, max_files: int = 2000) -> dict:
    if not data.startswith(b"PK"):
        return {}
    result = {"is_zip": False, "file_count": 0, "entries": [], "suspicious_entries": [], "zip_bomb_indicators": []}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            result["is_zip"] = True
            infos = zf.infolist()[:max_files]
            result["file_count"] = len(zf.infolist())
            total_uncompressed = 0
            total_compressed = 0
            for info in infos:
                total_uncompressed += info.file_size
                total_compressed += info.compress_size
                name_lower = info.filename.lower()
                suspicious = (
                    name_lower.endswith((".exe", ".dll", ".scr", ".ps1", ".js", ".jse", ".vbs", ".vbe", ".hta", ".lnk", ".iso"))
                    or "vbaProject.bin".lower() in name_lower
                    or "/embeddings/" in name_lower
                    or "/externalLinks/" in name_lower
                )
                entry = {"name": info.filename, "size": info.file_size, "compressed": info.compress_size}
                result["entries"].append(entry)
                if suspicious:
                    result["suspicious_entries"].append(entry)
            if total_compressed and total_uncompressed / total_compressed > 100:
                result["zip_bomb_indicators"].append("Uncompressed/compressed ratio exceeds 100x")
            if total_uncompressed > 2_000_000_000:
                result["zip_bomb_indicators"].append("Archive declares more than 2 GB uncompressed")
    except (zipfile.BadZipFile, OSError, ValueError) as exc:
        result["error"] = str(exc)
    return result


def office_metadata(data: bytes) -> dict:
    if not data.startswith(b"PK"):
        return {}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = [name for name in zf.namelist()]
            lower = [name.lower() for name in names]
            return {
                "ooxml": any(name.endswith("[content_types].xml") for name in lower),
                "vba_project": any(name.endswith("vbaproject.bin") for name in lower),
                "external_links": [name for name in names if "externallink" in name.lower()][:100],
                "embedded_objects": [name for name in names if "/embeddings/" in name.lower()][:100],
                "relationships": [name for name in names if name.endswith(".rels")][:100],
                "custom_xml": [name for name in names if "customxml" in name.lower()][:100],
            }
    except (zipfile.BadZipFile, OSError):
        return {}


def script_metadata(filename: str, data: bytes, strings: list[str]) -> dict:
    ext = Path(filename).suffix.lower()
    text = "\n".join(strings)
    return {
        "script_family": SCRIPT_EXTENSIONS.get(ext),
        "extension": ext,
        "encoded_powershell": bool(re.search(r"(?i)(-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]{20,})", text)),
        "javascript_eval": bool(re.search(r"(?i)\beval\s*\(|new\s+Function\s*\(|unescape\s*\(", text)),
        "download_execution": bool(
            re.search(r"(?i)(invoke-webrequest|downloadstring|bitsadmin|certutil|curl\s+.*-o|wget\s+.*-o)", text)
        ),
        "scripting_lolbins": sorted(
            marker
            for marker in ("mshta", "rundll32", "regsvr32", "wmic", "schtasks", "cscript", "wscript")
            if marker in text.lower()
        ),
    }


def packer_metadata(data: bytes) -> dict:
    found = []
    for family, markers in PACKER_MARKERS.items():
        if any(marker.lower() in data.lower() for marker in markers):
            found.append(family)
    return {"detected": found, "likely_packed": bool(found)}


def run_optional_yara(data: bytes) -> list[dict]:
    try:
        import yara  # type: ignore
    except Exception:
        return []
    rules_path = Path(__file__).resolve().parents[2] / "data" / "yara" / "phishhunter_rules.yar"
    if not rules_path.exists():
        return []
    try:
        rules = yara.compile(filepath=str(rules_path))
        matches = rules.match(data=data)
        return [{"rule": match.rule, "tags": match.tags, "meta": match.meta} for match in matches]
    except Exception:
        return []


def _yara_available() -> bool:
    try:
        import yara  # type: ignore
    except Exception:
        return False
    return yara is not None


def _risk_evidence(filekind: str, metadata: dict, findings: list[dict], iocs: dict, strings: list[str]) -> list[dict]:
    evidence: list[dict] = []
    name = metadata.get("name", {})
    if name.get("double_extension"):
        evidence.append({"signal": "double-extension", "severity": "high", "detail": name.get("suffixes", [])})
    if name.get("extension_content_mismatch"):
        evidence.append({"signal": "extension-content-mismatch", "severity": "high", "detail": f"{filekind} content uses a non-executable filename extension"})
    if metadata.get("api_signals"):
        evidence.append({"signal": "suspicious-api-imports", "severity": "high", "detail": metadata["api_signals"][:20]})
    if metadata.get("anti_analysis", {}).get("category_count", 0) >= 2:
        evidence.append({"signal": "anti-analysis-markers", "severity": "medium", "detail": metadata["anti_analysis"]["markers"]})
    if metadata.get("packer", {}).get("likely_packed"):
        evidence.append({"signal": "packer", "severity": "medium", "detail": metadata["packer"]["detected"]})
    if metadata.get("pdf", {}).get("suspicious"):
        evidence.append({"signal": "pdf-active-content", "severity": "high", "detail": metadata["pdf"]["indicators"]})
    if metadata.get("office", {}).get("vba_project"):
        evidence.append({"signal": "office-macro", "severity": "high", "detail": "VBA project present"})
    if metadata.get("archive", {}).get("zip_bomb_indicators"):
        evidence.append({"signal": "archive-risk", "severity": "high", "detail": metadata["archive"]["zip_bomb_indicators"]})
    if metadata.get("pe", {}).get("overlay_size", 0) > 1024:
        evidence.append({"signal": "pe-overlay", "severity": "medium", "detail": metadata["pe"]["overlay_size"]})
    high_entropy_sections = [
        section["name"] for section in metadata.get("pe", {}).get("sections", []) if section.get("high_entropy")
    ]
    if high_entropy_sections:
        evidence.append({"signal": "high-entropy-sections", "severity": "medium", "detail": high_entropy_sections})
    if iocs.get("urls"):
        evidence.append({"signal": "embedded-network-iocs", "severity": "medium", "detail": len(iocs["urls"])})
    if findings:
        evidence.append({"signal": "behavioral-markers", "severity": "high", "detail": len(findings)})
    if not findings and strings:
        evidence.append({"signal": "string-surface", "severity": "info", "detail": len(strings)})
    return evidence


def analyze_file(filename: str, data: bytes) -> dict:
    safe_filename = Path(filename).name
    hashes = hash_bytes(data)
    strings = strings_from_bytes(data, limit=8000)
    joined = "\n".join(strings)
    findings, techniques, behavior_score = behavior_findings(joined)
    iocs = extract_iocs(joined + "\n" + data[:2_000_000].decode("latin-1", errors="ignore"))
    filekind = file_type(data, safe_filename)
    metadata = {
        "mime_guess": mimetypes.guess_type(safe_filename)[0],
        "name": name_metadata(safe_filename, filekind),
        "byte_profile": byte_profile(data),
        "pe": pe_metadata(data),
        "elf": elf_metadata(data),
        "macho": macho_metadata(data),
        "pdf": pdf_metadata(data),
        "archive": archive_metadata(data),
        "office": office_metadata(data),
        "script": script_metadata(safe_filename, data, strings),
        "packer": packer_metadata(data),
    }
    metadata["pe_security"] = pe_security_metadata(metadata["pe"])
    metadata["api_signals"] = imported_api_signals(metadata["pe"], strings)
    metadata["anti_analysis"] = anti_analysis_metadata(data, strings)
    yara_matches = run_optional_yara(data)
    metadata["yara_matches"] = yara_matches
    metadata["yara_available"] = bool(yara_matches) or _yara_available()

    score = behavior_score
    score += 12 if entropy(data) >= 7.4 else 5 if entropy(data) >= 7.0 else 0
    score += min(18, len(iocs["urls"]) * 4)
    score += 15 if metadata["pdf"].get("suspicious") else 0
    score += 18 if metadata["office"].get("vba_project") else 0
    score += 20 if metadata["script"].get("encoded_powershell") else 0
    score += min(20, len(yara_matches) * 10)
    score += 12 if metadata["name"].get("double_extension") else 0
    score += 10 if metadata["name"].get("extension_content_mismatch") else 0
    score += min(18, len(metadata["api_signals"]) * 4)
    score += 6 if metadata["anti_analysis"].get("category_count", 0) >= 2 else 0
    score = min(100, int(score))
    verdict = "malicious/suspicious" if score >= 60 else "needs-review" if score >= 25 else "low-risk"
    evidence = _risk_evidence(filekind, metadata, findings, iocs, strings)
    correlation = correlate_evidence(iocs, techniques, evidence)

    return {
        "filename": safe_filename,
        "size": len(data),
        "type": filekind,
        "hashes": hashes,
        "entropy": round(entropy(data), 4),
        "strings": strings[:1000],
        "iocs": iocs,
        "metadata": metadata,
        "findings": findings,
        "mitre_techniques": techniques,
        "correlation": correlation,
        "attribution_guardrail": attribution_guardrail([item["id"] for item in techniques], len(iocs.get("ips", [])) + len(iocs.get("domains", []))),
        "evidence": evidence,
        "risk_score": score,
        "verdict": verdict,
        "analysis_engine": {
            "name": "PhishGuard Static Engine",
            "version": "2.5",
            "execution_performed": False,
            "dynamic_sandbox": "external-only",
            "optional_engines": {"yara": {"available": metadata["yara_available"], "matches": len(yara_matches)}},
        },
        "notes": [
            "Static analysis only; the sample was never executed by the web application host.",
            "ATT&CK mappings describe observed behavior signals and are not actor attribution.",
            "For live detonation, submit to a separately isolated sandbox host using the configured sandbox adapter.",
        ],
    }
