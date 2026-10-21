from ..parsers.logs import parse_log
def parse(text): return [x.as_dict() for x in parse_log(text,'dhcp','dhcp.log')]
