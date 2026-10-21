from ...parsers.zeek import parse_zeek
def parse(text,filename='conn.log'): return [x.as_dict() for x in parse_zeek(text,filename)]
