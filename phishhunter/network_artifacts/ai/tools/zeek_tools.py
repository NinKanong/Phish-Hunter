from ...analyzers.zeek.zeek_parser import parse
def analyze_zeek(text,filename='conn.log'): return parse(text,filename)
