"""Deep PCAP/network artifact module contract."""
TOOL_KEY="pcap-analyst"
DISPLAY_NAME="PCAP Analyst (Network Artifacts)"
CAPABILITIES=["PCAP/PCAPNG","Zeek","Suricata","NetFlow/IPFIX","firewall","proxy","DNS","DHCP","protocol analysis","timeline","graph","IOC extraction","ATT&CK","incident response","evidence locker","STIX/CSV/HTML/JSON exports"]
INTEGRATIONS=["Wireshark","tshark","Zeek","Suricata","Arkime","NetworkMiner","Security Onion","Brim","Wazuh","Velociraptor","MISP","OpenCTI","TheHive","Elastic","Splunk"]
def manifest(): return {"key":TOOL_KEY,"title":DISPLAY_NAME,"capabilities":CAPABILITIES,"integrations":INTEGRATIONS}
