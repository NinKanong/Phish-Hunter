# Analyzer Guide

## File evidence

For every uploaded artifact the report includes filename, type, MIME guess, size, MD5, SHA-1, SHA-256, SHA-512, entropy, ASCII strings sample, URLs/domains/IP/email indicators, suspicious extensions and command-execution keyword observations.

For bounded passive file candidates carved from TCP streams, the report includes extraction ID, stream, offset, size, magic/type, hashes, entropy, strings and archive listing when supported.

## Behaviour detections

- periodic beaconing candidate: regular repeated communication intervals
- DNS tunneling candidate: long/high-entropy DNS labels
- DGA-like candidate: lexical entropy/digit-ratio heuristic
- lateral movement candidate: internal administrative/service ports
- scanning candidate: high port/target fan-out
- high-volume transfer candidate: aggregate repeated transfer volume
- high-severity Suricata alert: preserved from source severity
- potential C2: repeated internal-to-public traffic plus port/timing evidence

All are heuristics. They require corroboration.
