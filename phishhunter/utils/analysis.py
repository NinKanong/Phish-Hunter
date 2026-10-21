from collections import Counter
import math
import re
from urllib.parse import unquote

SUSPICIOUS = [
    ("powershell", "T1059.001", 12, "Command and Scripting Interpreter: PowerShell"),
    ("cmd.exe", "T1059.003", 10, "Command and Scripting Interpreter: Windows Command Shell"),
    ("wscript", "T1059.005", 10, "Command and Scripting Interpreter: Visual Basic"),
    ("cscript", "T1059.005", 10, "Command and Scripting Interpreter: Visual Basic"),
    ("mshta", "T1218.005", 15, "System Binary Proxy Execution: Mshta"),
    ("rundll32", "T1218.011", 14, "System Binary Proxy Execution: Rundll32"),
    ("regsvr32", "T1218.010", 14, "System Binary Proxy Execution: Regsvr32"),
    ("certutil", "T1140", 12, "Deobfuscate/Decode Files or Information"),
    ("bitsadmin", "T1197", 12, "BITS Jobs"),
    ("schtasks", "T1053.005", 12, "Scheduled Task/Job: Scheduled Task"),
    ("wmic", "T1047", 12, "Windows Management Instrumentation"),
    ("winhttp", "T1071.001", 7, "Web Protocols"),
    ("websocket", "T1071.001", 8, "Web Protocols"),
    ("atob(", "T1027", 10, "Obfuscated/Compressed Files or Information"),
    ("frombase64string", "T1140", 12, "Deobfuscate/Decode Files or Information"),
    ("-enc ", "T1027", 14, "Obfuscated/Compressed Files or Information"),
    ("base64", "T1027", 8, "Obfuscated/Compressed Files or Information"),
    ("virtualalloc", "T1106", 12, "Native API"),
    ("createremotethread", "T1055", 15, "Process Injection"),
    ("writeprocessmemory", "T1055", 15, "Process Injection"),
    ("wininet", "T1071.001", 8, "Web Protocols"),
    ("urlmon", "T1105", 10, "Ingress Tool Transfer"),
    ("invoke-webrequest", "T1105", 12, "Ingress Tool Transfer"),
    ("downloadstring", "T1105", 12, "Ingress Tool Transfer"),
    ("new-object net.webclient", "T1105", 12, "Ingress Tool Transfer"),
    ("reg add", "T1112", 10, "Modify Registry"),
    ("reg.exe", "T1112", 8, "Modify Registry"),
    ("startup", "T1547", 7, "Boot or Logon Autostart Execution"),
    ("userinit", "T1547.004", 12, "Winlogon Helper DLL"),
    ("appdata", "T1105", 4, "User Execution / Staged Payload Location"),
]


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    size = len(data)
    return -sum((count / size) * math.log2(count / size) for count in counts.values())


def strings_from_bytes(data: bytes, minimum: int = 4, limit: int = 5000) -> list[str]:
    out: list[str] = []
    ascii_buf: list[str] = []
    for byte in data:
        if 32 <= byte <= 126:
            ascii_buf.append(chr(byte))
        else:
            if len(ascii_buf) >= minimum:
                out.append("".join(ascii_buf))
            ascii_buf = []
        if len(out) >= limit:
            break
    if len(ascii_buf) >= minimum and len(out) < limit:
        out.append("".join(ascii_buf))

    utf16_limit = max(0, limit - len(out))
    if utf16_limit:
        decoded = data.decode("utf-16le", errors="ignore")
        for part in re.findall(r"[\x20-\x7e]{%d,}" % minimum, decoded):
            out.append(part)
            if len(out) >= limit:
                break
    return out[:limit]


def normalize_text(text: str) -> str:
    text = unquote(text)
    return re.sub(r"\s+", " ", text).strip()


def behavior_findings(text: str):
    low = normalize_text(text).lower()
    findings: list[dict] = []
    techniques: dict[str, dict] = {}
    score = 0
    for marker, technique, points, name in SUSPICIOUS:
        hits = len(re.findall(re.escape(marker), low))
        if hits:
            confidence = "high" if points >= 14 else "medium"
            findings.append(
                {
                    "marker": marker,
                    "technique": technique,
                    "technique_name": name,
                    "hits": min(hits, 20),
                    "confidence": confidence,
                    "score": min(points * min(hits, 3), 30),
                }
            )
            techniques[technique] = {
                "id": technique,
                "name": name,
                "evidence_count": techniques.get(technique, {}).get("evidence_count", 0) + hits,
            }
            score += points * min(hits, 3)
    return findings, list(techniques.values()), min(100, score)
