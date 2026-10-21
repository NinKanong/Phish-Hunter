from dataclasses import dataclass
@dataclass
class FeedItem:
    source:str
    indicator:str
    kind:str

def normalize_item(source,indicator,kind): return FeedItem(source,indicator,kind)
