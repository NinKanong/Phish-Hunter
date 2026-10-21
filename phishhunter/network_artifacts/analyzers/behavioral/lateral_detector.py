from __future__ import annotations
ADMIN={22:'SSH',23:'Telnet',135:'RPC',139:'NetBIOS',445:'SMB',3389:'RDP',5985:'WinRM',5986:'WinRM',1433:'MSSQL',3306:'MySQL'}
def detect(events):
    out=[]
    for e in events:
        if e.get('src_ip') and e.get('dst_ip') and e.get('src_ip')!=e.get('dst_ip') and e.get('dst_port') in ADMIN:
            out.append({'source':e['src_ip'],'destination':e['dst_ip'],'port':e['dst_port'],'service':ADMIN[e['dst_port']],'timestamp':e.get('timestamp'),'confidence':55,'reason':'internal administrative/service-port observation'})
    return out[:1000]
