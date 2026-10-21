from __future__ import annotations
import base64, binascii, re
from typing import Any

HTTP_METHODS=("GET ","POST ","PUT ","PATCH ","DELETE ","HEAD ","OPTIONS ","CONNECT ")

def dissect_payload(payload: bytes, src_port: int|None=None, dst_port: int|None=None) -> dict[str,Any]:
    result={"http":None,"tls":None,"dns":None,"ftp":None,"smtp":None,"ssh":None,"indicators":{}}
    text=payload[:65536].decode("latin1","ignore")
    if text.startswith(HTTP_METHODS) or text.startswith("HTTP/"):
        lines=text.split("\r\n")
        headers={}
        for line in lines[1:100]:
            if ":" in line:
                k,v=line.split(":",1); headers[k.lower().strip()]=v.strip()[:2000]
        result["http"]={"first_line":lines[0][:2048],"headers":headers,"host":headers.get("host"),"user_agent":headers.get("user-agent"),"content_type":headers.get("content-type"),"content_length":headers.get("content-length"),"location":headers.get("location")}
    if len(payload)>=5 and payload[0] in {20,21,22,23} and payload[1]==3:
        result["tls"]={"record_type":payload[0],"version":f"{payload[1]}.{payload[2]}","length":int.from_bytes(payload[3:5],'big')}
    if payload.startswith(b"SSH-"):
        result["ssh"]={"banner":payload.split(b"\n",1)[0].decode("latin1","ignore")[:255]}
    if b"220 " in payload[:512] or b"EHLO " in payload[:512]:
        result["smtp"]={"banner_or_command":text[:1000]}
    if b"USER " in payload[:512] or b"RETR " in payload[:512]:
        result["ftp"]={"commands":re.findall(r"(?im)^(USER|PASS|RETR|STOR|CWD|LIST)\s+[^\r\n]{0,200}",text)[:50]}
    result["indicators"]={
        "urls":sorted(set(re.findall(r"https?://[^\s\"'<>]{3,500}",text,re.I)))[:100],
        "domains":sorted(set(re.findall(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b",text,re.I)))[:200],
    }
    return result
