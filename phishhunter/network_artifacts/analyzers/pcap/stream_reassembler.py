from __future__ import annotations
from collections import defaultdict
from typing import Any

class BoundedTCPReassembler:
    """Best-effort passive TCP reassembly with hard memory/segment limits.

    It does not perform TCP evasion normalization or retransmission-perfect
    reconstruction. It is intentionally bounded for an upload-analysis service.
    """
    def __init__(self, max_stream_bytes: int = 8_000_000, max_streams: int = 2000):
        self.max_stream_bytes=max_stream_bytes; self.max_streams=max_streams
        self.streams: dict[tuple, dict[int, bytes]] = defaultdict(dict)
        self.meta: dict[tuple, dict[str, Any]] = {}
    def add(self, key: tuple, seq: int, payload: bytes, meta: dict[str,Any]|None=None):
        if not payload or len(self.streams) >= self.max_streams and key not in self.streams: return
        total=sum(len(x) for x in self.streams[key].values())
        if total >= self.max_stream_bytes: return
        self.streams[key][seq]=payload[:max(0,self.max_stream_bytes-total)]
        if meta: self.meta.setdefault(key, {}).update(meta)
    def streams_as_bytes(self) -> list[dict[str,Any]]:
        out=[]
        for key, segments in self.streams.items():
            data=bytearray(); expected=None
            for seq,payload in sorted(segments.items()):
                if expected is None: expected=seq
                if seq < expected:
                    continue
                if seq > expected and data:
                    # Preserve a gap marker rather than pretending bytes are contiguous.
                    data.extend(b"\n[K4_TCP_GAP]\n")
                data.extend(payload); expected=seq+len(payload)
                if len(data)>=self.max_stream_bytes: break
            out.append({"key":key,"bytes":bytes(data[:self.max_stream_bytes]),"segments":len(segments),"meta":self.meta.get(key,{})})
        return out
