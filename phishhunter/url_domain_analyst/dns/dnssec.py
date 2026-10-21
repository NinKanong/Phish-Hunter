from __future__ import annotations

def posture(records: dict) -> dict:
    dnskey=records.get("DNSKEY",[]) or []; ds=records.get("DS",[]) or []; rrsig=records.get("RRSIG",[]) or []
    return {"enabled":bool(dnskey or ds),"dnskey_count":len(dnskey),"ds_count":len(ds),"rrsig_count":len(rrsig),
            "chain_complete_candidate":bool(dnskey and ds and rrsig),
            "note":"This is a posture signal; full cryptographic validation belongs to an authoritative resolver module."}
