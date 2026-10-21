from ...parsers.suricata import parse_suricata
def parse(text): return [x.as_dict() for x in parse_suricata(text)]
