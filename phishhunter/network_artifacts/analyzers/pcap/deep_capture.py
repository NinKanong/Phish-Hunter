from __future__ import annotations
from datetime import datetime, timezone
from typing import Any
from phishhunter.analyzers.pcap.analyzer import _classic_pcap, _pcapng, _packet_fields
from .stream_reassembler import BoundedTCPReassembler
from .protocol_dissector import dissect_payload
from .file_extractor import extract_embedded_files


def _payload_offset(packet: bytes) -> int|None:
    if len(packet)<14: return None
    ethertype=int.from_bytes(packet[12:14],'big'); off=14
    if ethertype in (0x8100,0x88A8) and len(packet)>=18:
        ethertype=int.from_bytes(packet[16:18],'big'); off=18
    if ethertype==0x0800:
        if len(packet)<off+20:return None
        ihl=(packet[off]&0x0f)*4
        if ihl<20 or len(packet)<off+ihl:return None
        proto=packet[off+9]; l4=off+ihl
    elif ethertype==0x86dd:
        if len(packet)<off+40:return None
        proto=packet[off+6]; l4=off+40
    else:return None
    if proto==6:
        if len(packet)<l4+20:return None
        doff=((packet[l4+12]>>4)&0xf)*4
        return min(len(packet),l4+max(20,doff))
    if proto==17:
        return min(len(packet),l4+8) if len(packet)>=l4+8 else None
    return None


def deep_pcap_capture(data: bytes, max_packets: int=200_000) -> dict[str,Any]:
    if data[:4] in {b"\x0a\x0d\x0d\x0a"}:
        link,snap,records=_pcapng(data)
        fmt="pcapng"
    else:
        link,snap,records=_classic_pcap(data)
        fmt="pcap"
    reassembler=BoundedTCPReassembler()
    protocol_stats={}
    conversations={}
    http_transactions=[]; tls_observations=[]; dns_observations=[]; stream_offsets={}
    for idx,(ts,raw) in enumerate(records[:max_packets]):
        fields=_packet_fields(raw)
        proto=str(fields.get('protocol') or 'unknown')
        protocol_stats[proto]=protocol_stats.get(proto,0)+1
        key=(fields.get('src'),fields.get('dst'),fields.get('sport'),fields.get('dport'),proto)
        conv=conversations.setdefault(key,{'packets':0,'bytes':0,'first_seen':ts,'last_seen':ts,'protocol':proto})
        conv['packets']+=1; conv['bytes']+=len(raw); conv['last_seen']=ts
        po=_payload_offset(raw)
        payload=raw[po:] if po is not None else b''
        if fields.get('http'):
            http_transactions.append({'timestamp':datetime.fromtimestamp(ts,timezone.utc).isoformat(),'src_ip':fields.get('src'),'src_port':fields.get('sport'),'dst_ip':fields.get('dst'),'dst_port':fields.get('dport'),'details':fields.get('http')})
        if fields.get('tls_sni'):
            tls_observations.append({'timestamp':datetime.fromtimestamp(ts,timezone.utc).isoformat(),'src_ip':fields.get('src'),'dst_ip':fields.get('dst'),'dst_port':fields.get('dport'),'sni':fields.get('tls_sni')})
        if fields.get('dns'):
            dns_observations.append({'timestamp':datetime.fromtimestamp(ts,timezone.utc).isoformat(),'src_ip':fields.get('src'),'dst_ip':fields.get('dst'),'details':fields.get('dns')})
        if proto=='TCP' and payload and fields.get('src') and fields.get('dst'):
            seq=stream_offsets.get(key,0)
            stream_offsets[key]=seq+len(payload)
            reassembler.add(key,seq,payload,{'src_ip':fields.get('src'),'dst_ip':fields.get('dst'),'src_port':fields.get('sport'),'dst_port':fields.get('dport'),'protocol':'TCP'})
    streams=reassembler.streams_as_bytes()
    for stream in streams:
        data_b=stream['bytes']
        stream['dissection']=dissect_payload(data_b,stream.get('meta',{}).get('src_port'),stream.get('meta',{}).get('dst_port'))
    extracted=extract_embedded_files(streams)
    serial_conversations=[]
    for key,v in conversations.items():
        serial_conversations.append({'src_ip':key[0],'dst_ip':key[1],'src_port':key[2],'dst_port':key[3],'protocol':key[4],'packets':v['packets'],'bytes':v['bytes'],'first_seen':datetime.fromtimestamp(v['first_seen'],timezone.utc).isoformat(),'last_seen':datetime.fromtimestamp(v['last_seen'],timezone.utc).isoformat()})
    return {
        'format':fmt,'link_type':link,'snaplen':snap,'raw_packet_count':len(records),'parsed_packet_count':min(len(records),max_packets),
        'protocol_statistics':dict(sorted(protocol_stats.items(),key=lambda x:-x[1])),
        'conversations':sorted(serial_conversations,key=lambda x:-x['bytes'])[:10000],
        'tcp_streams':[{k:v for k,v in s.items() if k!='bytes'}|{'byte_length':len(s.get('bytes',b''))} for s in streams[:2000]],
        'http_transactions':http_transactions[:5000],'tls_observations':tls_observations[:5000],'dns_observations':dns_observations[:5000],
        'extracted_files':extracted,
        'limits':{'max_packets':max_packets,'max_stream_bytes':8_000_000,'max_extracted_files':200,'max_extracted_file_bytes':8_000_000},
    }
