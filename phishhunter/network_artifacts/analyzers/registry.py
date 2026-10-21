from __future__ import annotations
from typing import Any,Callable

REGISTRY:dict[str,Callable[...,Any]]={}

def register(name):
    def deco(factory): REGISTRY[name]=factory; return factory
    return deco

def discover()->list[str]: return sorted(REGISTRY)

def get(name): return REGISTRY[name]

# Built-in routing catalog. Heavy imports are intentionally lazy.
for _name in ('pcap','zeek','suricata','netflow','firewall','proxy','dns','dhcp'):
    REGISTRY.setdefault(_name,_name)
