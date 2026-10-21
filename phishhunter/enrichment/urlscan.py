import httpx
from phishhunter.enrichment.base import EnrichmentResult
class URLScanConnector:
    name="urlscan.io"
    def __init__(self, api_key:str): self.api_key=api_key
    async def search_url(self, url:str)->EnrichmentResult:
        async with httpx.AsyncClient(timeout=15) as client:
            r=await client.get("https://urlscan.io/api/v1/search/",params={"q":f"page.url:{url}"},headers={"API-Key":self.api_key})
        found=r.status_code==200 and bool(r.json().get("results"))
        return EnrichmentResult(self.name,url,found,None,r.json() if r.headers.get("content-type","").startswith("application/json") else {"status":r.status_code})
