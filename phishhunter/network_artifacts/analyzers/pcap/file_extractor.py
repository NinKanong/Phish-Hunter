from __future__ import annotations
import re, struct
from typing import Any
from ...utils.file_utils import static_profile, archive_listing

MAGICS=[(b"MZ", "pe"),(b"\x7fELF","elf"),(b"%PDF-","pdf"),(b"PK\x03\x04","zip"),(b"\x89PNG","png"),(b"\xff\xd8\xff","jpeg"),(b"GIF8","gif"),(b"\x1f\x8b\x08","gzip"),(b"Rar!","rar")]

def _candidates(data: bytes, limit: int=100) -> list[tuple[int,str]]:
    out=[]
    for magic,name in MAGICS:
        start=0
        while len(out)<limit:
            idx=data.find(magic,start)
            if idx<0: break
            out.append((idx,name)); start=idx+1
    return sorted(out)[:limit]

def extract_embedded_files(streams: list[dict[str,Any]], max_files:int=200, max_file_bytes:int=8_000_000) -> list[dict[str,Any]]:
    files=[]
    for stream in streams:
        data=stream.get("bytes",b"")
        for index,(offset,kind) in enumerate(_candidates(data),1):
            if len(files)>=max_files: return files
            end=len(data)
            nxt=[p for p,_ in _candidates(data[offset+1:],limit=10)]
            if nxt:
                end=min(end, offset+1+nxt[0])
            chunk=data[offset:min(end,offset+max_file_bytes)]
            if len(chunk)<16: continue
            filename=f"extracted-{len(files)+1:04d}.{kind}"
            profile=static_profile(chunk,filename)
            files.append({
                "id":f"NETFILE-{len(files)+1:05d}","source_stream":str(stream.get("key")),"offset":offset,"size":len(chunk),
                "kind":kind,"filename":filename,"hashes":profile["hashes"],"sha256":profile["sha256"],
                "profile":profile,"archive":archive_listing(chunk,filename) if kind in {"zip","gzip"} else {"supported":False,"entries":[]},
                "extraction_note":"Best-effort passive signature-based carving; reconstruction gaps may affect file boundaries.",
            })
    return files
