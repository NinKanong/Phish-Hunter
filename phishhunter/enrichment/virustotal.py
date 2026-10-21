import httpx
from phishhunter.enrichment.base import EnrichmentResult
class VirusTotalConnector:
    name="VirusTotal"
    def __init__(self, api_key:str): self.api_key=api_key
    async def lookup_hash(self, sha256:str)->EnrichmentResult:
        async with httpx.AsyncClient(timeout=15) as client:
            r=await client.get(f"https://www.virustotal.com/api/v3/files/{sha256}",headers={"x-apikey":self.api_key})
        if r.status_code==200:
            data=r.json().get("data",{}).get("attributes",{})
            stats=data.get("last_analysis_stats",{})
            score=int(stats.get("malicious",0)) if stats else None
            return EnrichmentResult(self.name,sha256,True,score,data)
        return EnrichmentResult(self.name,sha256,False,None,{"status":r.status_code})
