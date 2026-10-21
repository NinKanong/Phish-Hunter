from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Iterable

@dataclass(frozen=True)
class SourceSpec:
    name: str
    category: str
    source_type: str
    access: str
    auth: str
    evidence: str
    enabled_by_default: bool = False

CATEGORIES = [
    ('search_engine', 'Search Engine OSINT', 40),
    ('social_media', 'Social Media OSINT', 60),
    ('code_repository', 'Code Repository OSINT', 50),
    ('documents_files', 'Document & File OSINT', 40),
    ('image_media', 'Image & Media OSINT', 30),
    ('email_identity', 'Email & Identity OSINT', 40),
    ('corporate_business', 'Corporate & Business OSINT', 60),
    ('people', 'Person & People OSINT', 40),
    ('domain_dns', 'Domain & DNS OSINT', 30),
    ('threat_intel', 'Threat Intel OSINT', 40),
    ('breach_exposure', 'Breach & Leak OSINT', 30),
    ('dark_web', 'Dark Web OSINT', 25),
    ('geospatial', 'Geospatial OSINT', 20),
    ('financial_crypto', 'Financial & Crypto OSINT', 20),
    ('legal_public_records', 'Legal & Public Records OSINT', 20),
]

# Sources explicitly requested by the user's blueprint, plus widely-used public/authorized feeds.
SOURCE_SEEDS = {
 'search_engine': ['Google Search','Bing Search','Yandex Search','DuckDuckGo','Baidu Search','Naver Search','Brave Search','Mojeek','Google News','Bing News','Google Images','Bing Images','Yandex Images'],
 'social_media': ['LinkedIn','X','Facebook','Instagram','TikTok','YouTube','GitHub','GitLab','Reddit','Telegram','Discord','Mastodon','Bluesky','Pinterest','Medium','Dev.to','Stack Overflow','Hacker News','Product Hunt','Crunchbase','AngelList / Wellfound','Glassdoor','Indeed','Meetup','Twitch','Vimeo','Flickr','Tumblr','Quora','Keybase'],
 'code_repository': ['GitHub API','GitLab API','Bitbucket API','SourceForge','Gitea','Codeberg','npm Registry','PyPI','Maven Central','Docker Hub','grep.app','PublicWWW','Libraries.io','Packagist','RubyGems','NuGet Gallery','Crates.io','Go Packages','Homebrew Formulae','Repology'],
 'documents_files': ['Google Dorks','Bing Dorks','Wayback Machine','Common Crawl','DocumentCloud','Scribd','SlideShare','Issuu','Google Drive public search','Internet Archive','OpenLibrary','HathiTrust','Crossref','Zenodo','Figshare','arXiv','PubMed','CORE','Semantic Scholar','Wikimedia Commons'],
 'image_media': ['Google Images','Bing Visual Search','Yandex Images','TinEye','Google Lens','Karma Decay','Wikimedia Commons','Flickr','ExifTool','MediaInfo','InVID','YouTube','Vimeo','Archive.org Media','Openverse'],
 'email_identity': ['Hunter.io','EmailRep','Have I Been Pwned','DeHashed','LeakCheck','IntelX','Snusbase','RocketReach','Clearbit','Snov.io','FindThatEmail','VoilaNorbert','Gravatar','EmailCrawl','WhoisXML Email Verification'],
 'corporate_business': ['Companies House','SEC EDGAR','OpenCorporates','Crunchbase','PitchBook','Dun & Bradstreet','Bloomberg','Reuters','ZoomInfo','Glassdoor','Indeed','LinkedIn Company Pages','GLEIF LEI Search','OpenSanctions','UK Charity Commission','EU Transparency Register','US SAM.gov','USASpending','FDIC BankFind','FCA Register','ASIC Registers','ACRA Singapore','Canadian Corporations','India MCA','Cambodia Business Registration'],
 'people': ['Sherlock','Maigret','WhatsMyName','Namechk','KnowEm','Holehe','GHunt','Blackbird','IntelTechniques','Pipl','Spokeo','Whitepages','BeenVerified','TruthFinder','PeekYou','Gravatar','Keybase','Have I Been Pwned','GitHub Search','LinkedIn Search'],
 'domain_dns': ['SecurityTrails','VirusTotal Passive DNS','DNSDB','RiskIQ PassiveTotal','CIRCL Passive DNS','Mnemonic','DNSlytics','SpyOnWeb','ViewDNS','WhoisXML API','Robtex','ThreatMiner','Cisco Umbrella Investigate','DNSDumpster','crt.sh','CertSpotter','Censys','DomainTools','Amass','Subfinder','Assetfinder','Findomain','dnsx','DNSRecon','Fierce','MassDNS','PureDNS','ShuffleDNS','Sublist3r','RapidDNS'],
 'threat_intel': ['AlienVault OTX','MISP','OpenCTI','VirusTotal','AbuseIPDB','GreyNoise','Spamhaus','URLhaus','OpenPhish','PhishTank','ThreatFox','Feodo Tracker','MalwareBazaar','Cisco Talos','IBM X-Force','Recorded Future','Mandiant','CrowdStrike','SANS ISC','Shadowserver','CISA KEV','NVD','MITRE ATT&CK','Malpedia','ThreatMiner'],
 'breach_exposure': ['Have I Been Pwned','IntelX','DeHashed','Hudson Rock','SpyCloud','Constella','LeakCheck','Snusbase','BreachDirectory','Leak-Lookup','Scattered Secrets','Mozilla Monitor'],
 'dark_web': ['Ahmia','Tor Project','OnionSearch','OnionLand Search','Haystak','Kilos','DarkSearch','IntelX Dark Web','Recorded Future Dark Web','Flashpoint','Searchlight Cyber','SOCRadar Dark Web','KELA','DarkOwl','BreachForums monitoring via authorized feed'],
 'geospatial': ['OpenStreetMap','Nominatim','GeoNames','MaxMind GeoIP','IPinfo','Google Maps','Bing Maps','Mapillary','Wikimedia Geosearch','Sentinel Hub','NASA Worldview','USGS','OpenAerialMap','SunCalc','ExifTool'],
 'financial_crypto': ['Etherscan','Blockchair','Blockstream Explorer','BTC.com','TRONSCAN','Solscan','Arkham','Chainalysis','TRM Labs','Elliptic','OFAC Sanctions','SEC EDGAR','Companies House','OpenCorporates'],
 'legal_public_records': ['OFAC Sanctions','EU Sanctions Map','UN Security Council Sanctions','UK Sanctions List','OpenSanctions','PACER','CourtListener','RECAP Archive','SEC EDGAR','Companies House','SAM.gov','GLEIF','FATF','Interpol Red Notices','World Bank Debarred Firms'],
}

def _access_for(name: str) -> tuple[str,str,str]:
    n=name.lower()
    if 'api' in n or any(x in n for x in ('virus','securitytrails','shodan','censys','hunter','hibp','dehashed','ipinfo','maxmind','gleif','sec edgar','companies house')):
        return 'api','api-key-or-oauth','provider-returned records'
    if any(x in n for x in ('dark web','tor','onion','haystak','kilos','flashpoint','darkowl','kela')):
        return 'authorized-feed','connector-required','provider-confirmed dark-web intelligence'
    if any(x in n for x in ('archive','common crawl','wayback')):
        return 'archive','public','archived/public records'
    return 'public-web','terms-dependent','public indexed metadata; no bypass'

def build_source_catalog(minimum: int = 360) -> list[dict]:
    rows=[]
    seen=set()
    for category, _, _count in CATEGORIES:
        for seed in SOURCE_SEEDS.get(category, []):
            if seed.lower() in seen: continue
            access,auth,evidence=_access_for(seed)
            rows.append(asdict(SourceSpec(seed,category,'provider-or-public-source',access,auth,evidence,False)))
            seen.add(seed.lower())
    # Keep a balanced adapter contract for categories with fewer named sources. These are
    # implementation slots, not claims that a third-party service exists or is connected.
    by_cat={c:sum(1 for r in rows if r['category']==c) for c,_,_ in CATEGORIES}
    for category, title, _count in CATEGORIES:
        while by_cat[category] < 12 and len(rows) < minimum:
            n=by_cat[category]+1
            rows.append(asdict(SourceSpec(f'{title} Provider Adapter {n:02d}',category,'adapter-contract','provider-adapter','configuration-required','normalized provider evidence',False)))
            by_cat[category]+=1
    i=1
    while len(rows) < minimum:
        category,title,_=CATEGORIES[(i-1)%len(CATEGORIES)]
        rows.append(asdict(SourceSpec(f'{title} Adapter {i:03d}',category,'adapter-contract','provider-adapter','configuration-required','normalized provider evidence',False)))
        i+=1
    return rows

def source_catalog_stats(rows: Iterable[dict]) -> dict:
    rows=list(rows)
    return {'total':len(rows),'by_category':{c:sum(1 for r in rows if r['category']==c) for c,_,_ in CATEGORIES},'enabled':sum(1 for r in rows if r.get('enabled_by_default'))}
