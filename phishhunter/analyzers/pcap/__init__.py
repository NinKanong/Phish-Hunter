"""Lightweight, safe PCAP metadata and flow analyzer.

The analyzer intentionally parses packet metadata without executing payloads.
It supports classic PCAP files and produces deterministic evidence suitable for
an analyst dashboard. Optional protocol dissectors can enrich the result later.
"""
from .analyzer import analyze_pcap

__all__ = ["analyze_pcap"]
