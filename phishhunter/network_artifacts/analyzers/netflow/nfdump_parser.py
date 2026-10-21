from ...parsers.netflow import parse_netflow
def parse(text): return [x.as_dict() for x in parse_netflow(text)]
