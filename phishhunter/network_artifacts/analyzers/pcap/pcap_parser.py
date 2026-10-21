from phishhunter.analyzers.pcap.analyzer import analyze_pcap
from .deep_capture import deep_pcap_capture

def parse(data:bytes)->dict:
    base=analyze_pcap(data); base['deep_capture']=deep_pcap_capture(data); return base
