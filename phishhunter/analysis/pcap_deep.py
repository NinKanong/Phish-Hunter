from __future__ import annotations

from collections import Counter, defaultdict
from statistics import mean, pstdev
from datetime import datetime, timezone
import math, ipaddress, re


def _public(v):
    try: return ipaddress.ip_address(v).is_global
    except Exception: return False

def _private(v):
    try: return ipaddress.ip_address(v).is_private
    except Exception: return False

def _entropy(text: str) -> float:
    if not text: return 0.0
    c=Counter(text); n=len(text)
    return -sum((x/n)*math.log2(x/n) for x in c.values())

def augment_pcap(result: dict) -> dict:
    packets=result.get('sample_packets') or []
    flows=result.get('flows') or []
    dns=result.get('dns') or []
    protocol_counts=Counter(result.get('protocols') or {})
    total_packets=max(1,int(result.get('packet_count',0) or 0))
    total_bytes=max(1,int(result.get('total_bytes',0) or 0))
    result['protocol_hierarchy']=[{'protocol':p,'packets':n,'bytes_estimate':round(total_bytes*n/total_packets),'percentage':round(n*100/total_packets,3),'anomalies':[]} for p,n in protocol_counts.most_common()]
    conversations=[]
    for f in flows[:10000]:
        duration=0.0
        try:
            a=datetime.fromisoformat(str(f.get('first_seen')).replace('Z','+00:00')); b=datetime.fromisoformat(str(f.get('last_seen')).replace('Z','+00:00')); duration=max(0,(b-a).total_seconds())
        except Exception: pass
        packets_n=int(f.get('packets',0) or 0); bytes_n=int(f.get('bytes',0) or 0)
        score=0; reasons=[]
        dst=f.get('dst'); dport=f.get('dport')
        if _private(str(f.get('src',''))) and _public(str(dst or '')):
            score += 15; reasons.append('internal-to-public flow')
        if dport in {4444,5555,1337,31337,9001}: score += 35; reasons.append('commonly abused remote-control port')
        if packets_n >= 10: score += 10; reasons.append('repeated packet exchange')
        conversations.append({**f,'duration_seconds':round(duration,6),'packets_per_second':round(packets_n/max(duration,1e-6),4),'bytes_per_second':round(bytes_n/max(duration,1e-6),4),'suspicion_score':min(100,score),'reasons':reasons,'verdict':'review' if score else 'observed'})
    result['conversations']=conversations

    endpoint_map=defaultdict(lambda:{'packets_sent':0,'packets_received':0,'bytes_sent':0,'bytes_received':0,'public_peers':set(),'ports':Counter()})
    for f in flows:
        s,d=str(f.get('src') or ''),str(f.get('dst') or ''); b=int(f.get('bytes',0) or 0); p=int(f.get('packets',0) or 0)
        if s:
            e=endpoint_map[s]; e['packets_sent']+=p; e['bytes_sent']+=b; e['ports'][str(f.get('dport'))]+=p
            if _public(d): e['public_peers'].add(d)
        if d:
            e=endpoint_map[d]; e['packets_received']+=p; e['bytes_received']+=b
            if _public(s): e['public_peers'].add(s)
    result['endpoint_profiles']=[{'ip':ip,'scope':'private' if _private(ip) else 'public' if _public(ip) else 'other',**{k:v for k,v in e.items() if k!='public_peers'},'public_peers':sorted(e['public_peers'])[:100],'suspicion':min(100,len(e['public_peers'])*8)} for ip,e in sorted(endpoint_map.items(),key=lambda x:-(x[1]['bytes_sent']+x[1]['bytes_received']))[:500]]

    dns_tunnels=[]; dga=[]
    for q in dns:
        for question in q.get('questions',[]):
            name=str(question.get('name') or '').lower().rstrip('.')
            labels=name.split('.')
            if not name: continue
            max_label=max((len(x) for x in labels),default=0)
            ent=max((_entropy(x) for x in labels),default=0)
            digit_ratio=sum(c.isdigit() for c in name)/max(1,len(name))
            if max_label>=35 or ent>=4.1:
                dns_tunnels.append({'query':name,'max_label_length':max_label,'entropy':round(ent,3),'digit_ratio':round(digit_ratio,3),'evidence':'long/high-entropy DNS label','confidence':55})
            if len(labels)>=2 and ent>=3.6 and digit_ratio>=0.12:
                dga.append({'domain':name,'entropy':round(ent,3),'digit_ratio':round(digit_ratio,3),'label_count':len(labels),'confidence':50})
    result['dns_tunneling_candidates']=dns_tunnels[:500]
    result['dga_candidates']=dga[:500]

    beacons=[]
    grouped=defaultdict(list)
    for f in flows:
        key=(f.get('src'),f.get('dst'),f.get('dport'),f.get('protocol'))
        for k in ('first_seen','last_seen'):
            try: grouped[key].append(datetime.fromisoformat(str(f[k]).replace('Z','+00:00')).timestamp())
            except Exception: pass
    for key,times in grouped.items():
        times=sorted(set(times));
        if len(times)<4: continue
        intervals=[b-a for a,b in zip(times,times[1:]) if b>a]
        if len(intervals)<3: continue
        avg=mean(intervals); cv=pstdev(intervals)/avg if avg else 99
        if cv<0.35:
            beacons.append({'source':key[0],'destination':key[1],'port':key[2],'protocol':key[3],'observations':len(times),'mean_interval_seconds':round(avg,3),'coefficient_variation':round(cv,4),'confidence':round(max(0,min(100,90-cv*150)),1),'reason':'regular repeated communication interval'})
    result['beaconing_candidates']=beacons[:500]

    lateral=[]
    admin_ports={22,23,135,139,445,3389,5985,5986,1433,3306}
    for f in flows:
        if _private(str(f.get('src') or '')) and _private(str(f.get('dst') or '')) and f.get('dport') in admin_ports:
            lateral.append({'source':f.get('src'),'destination':f.get('dst'),'destination_port':f.get('dport'),'protocol':f.get('protocol'),'packets':f.get('packets'),'bytes':f.get('bytes'),'first_seen':f.get('first_seen'),'last_seen':f.get('last_seen'),'confidence':55,'reason':'internal administrative/service-port communication'})
    result['lateral_movement_candidates']=lateral[:500]

    result['fingerprints']={
        'JA3':[], 'JA3S':[], 'JA4':[], 'JA4S':[], 'JA4H':[], 'JA4X':[], 'HASSH':[], 'HASSHServer':[], 'p0f':[],
        'status':'passive parser does not synthesize unavailable fingerprints; provider/parser integration may populate these arrays.'
    }
    result['file_carving']={'status':'not_performed','reason':'Bounded parser does not reconstruct arbitrary files from packet streams; use an authorized full forensic carving pipeline for this evidence.'}
    result['credential_observations']={'status':'redacted','records':[],'reason':'The parser does not retain plaintext credentials from packet payloads.'}
    return result
