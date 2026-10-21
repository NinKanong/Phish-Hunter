from collections import defaultdict
def detect(events):
    by_src=defaultdict(int)
    for e in events: by_src[e.get('src_ip')]+=int(e.get('bytes') or 0)
    return [{'source':s,'bytes':b,'reason':'high aggregate flow volume candidate'} for s,b in sorted(by_src.items(),key=lambda x:-x[1])[:100] if b>=10_000_000]
