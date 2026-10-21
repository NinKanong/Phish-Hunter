from __future__ import annotations

from dataclasses import dataclass, asdict
from urllib.parse import quote_plus


@dataclass(frozen=True)
class DirectLink:
    id: str
    category: str
    name: str
    url: str
    access: str = "public-web"
    auto_search: bool = True
    note: str = "Target is prefilled where the provider supports search URLs."


# Conservative, user-clickable public/search URLs. These do not bypass access controls.
_TEMPLATES: dict[str, list[tuple[str, str, str, bool, str]]] = {
    "search_engine": [
        ("Google", "https://www.google.com/search?q=site%3A{q}", "public-web", True, "Indexed pages"),
        ("Bing", "https://www.bing.com/search?q=site%3A{q}", "public-web", True, "Indexed pages"),
        ("DuckDuckGo", "https://duckduckgo.com/?q=site%3A{q}", "public-web", True, "Indexed pages"),
        ("Brave Search", "https://search.brave.com/search?q=site%3A{q}", "public-web", True, "Indexed pages"),
        ("Yandex", "https://yandex.com/search/?text=site%3A{q}", "public-web", True, "Indexed pages"),
    ],
    "social_media": [
        ("Reddit", "https://www.reddit.com/search/?q={q}", "public-web", True, "Public mentions"),
        ("X Search", "https://x.com/search?q={q}", "public-web", True, "Public posts where indexed"),
        ("YouTube", "https://www.youtube.com/results?search_query={q}", "public-web", True, "Public videos"),
        ("TikTok", "https://www.tiktok.com/search?q={q}", "public-web", True, "Public results"),
        ("LinkedIn Companies", "https://www.linkedin.com/search/results/companies/?keywords={q}", "login-dependent", True, "May require sign-in"),
    ],
    "code_repository": [
        ("GitHub Code", "https://github.com/search?q={q}&type=code", "public-web", True, "Public code references"),
        ("GitHub Repositories", "https://github.com/search?q={q}&type=repositories", "public-web", True, "Public repositories"),
        ("GitLab", "https://gitlab.com/search?search={q}", "public-web", True, "Public projects"),
        ("grep.app", "https://grep.app/search?q={q}", "public-web", True, "Indexed source text"),
        ("Sourcegraph", "https://sourcegraph.com/search?q=context%3Aglobal+{q}", "public-web", True, "Indexed source"),
    ],
    "documents_files": [
        ("Wayback URLs", "https://web.archive.org/web/*/{q}/*", "archive", True, "Historical web captures"),
        ("Wayback CDX", "https://web.archive.org/cdx/search/cdx?url=*.{q}/*&output=json&filter=statuscode:200", "archive", True, "Historical URL index"),
        ("Internet Archive", "https://archive.org/search?query={q}", "archive", True, "Public archive records"),
        ("Common Crawl Index", "https://index.commoncrawl.org/", "archive", False, "Search target in the Common Crawl index"),
        ("DocumentCloud", "https://www.documentcloud.org/search?q={q}", "public-web", True, "Public documents"),
    ],
    "image_media": [
        ("Google Images", "https://www.google.com/search?tbm=isch&q={q}", "public-web", True, "Public indexed images"),
        ("Bing Images", "https://www.bing.com/images/search?q={q}", "public-web", True, "Public indexed images"),
        ("Yandex Images", "https://yandex.com/images/search?text={q}", "public-web", True, "Public indexed images"),
        ("Internet Archive", "https://archive.org/search?query={q}", "archive", True, "Archived media"),
        ("Wikimedia Search", "https://commons.wikimedia.org/w/index.php?search={q}&title=Special%3AMediaSearch", "public-web", True, "Public media"),
    ],
    "email_identity": [
        ("Hunter", "https://hunter.io/", "login-dependent", False, "Use the domain field in Hunter"),
        ("Have I Been Pwned", "https://haveibeenpwned.com/DomainSearch", "login-dependent", False, "Domain search; access may require verification"),
        ("Mozilla Monitor", "https://monitor.mozilla.org/", "public-web", False, "Exposure lookup"),
        ("Gravatar", "https://gravatar.com/", "public-web", False, "Public profile search"),
        ("EmailRep", "https://emailrep.io/", "api-dependent", False, "Email reputation API/UI"),
    ],
    "corporate_business": [
        ("OpenCorporates", "https://opencorporates.com/companies?q={q}", "public-web", True, "Public company registry index"),
        ("Companies House", "https://find-and-update.company-information.service.gov.uk/search/companies?q={q}", "public-web", True, "UK public company records"),
        ("SEC EDGAR", "https://www.sec.gov/edgar/search/#/q={q}", "public-web", True, "US public filings"),
        ("OpenSanctions", "https://www.opensanctions.org/search/?q={q}", "public-web", True, "Public sanctions/entity search"),
        ("GLEIF", "https://search.gleif.org/", "public-web", False, "Global legal entity identifier search"),
    ],
    "people": [
        ("Google", "https://www.google.com/search?q=%22{q}%22+people", "public-web", True, "Public indexed references"),
        ("Bing", "https://www.bing.com/search?q=%22{q}%22+people", "public-web", True, "Public indexed references"),
        ("LinkedIn", "https://www.linkedin.com/search/results/all/?keywords={q}", "login-dependent", True, "May require sign-in"),
        ("GitHub", "https://github.com/search?q={q}&type=users", "public-web", True, "Public user profiles"),
        ("GitLab", "https://gitlab.com/search?search={q}", "public-web", True, "Public user/project references"),
    ],
    "domain_dns": [
        ("DNSDumpster", "https://dnsdumpster.com/", "public-web", False, "Use the domain in the site search"),
        ("crt.sh", "https://crt.sh/?q=%25.{q}", "public-web", True, "Certificate Transparency"),
        ("SecurityTrails", "https://securitytrails.com/domain/{q}", "login-dependent", True, "Domain intelligence; account may be required"),
        ("VirusTotal", "https://www.virustotal.com/gui/domain/{q}", "public-web", True, "Domain intelligence"),
        ("Who.is", "https://who.is/whois/{q}", "public-web", True, "WHOIS lookup"),
        ("ViewDNS", "https://viewdns.info/", "public-web", False, "Select the relevant DNS tool"),
    ],
    "threat_intel": [
        ("VirusTotal", "https://www.virustotal.com/gui/domain/{q}", "public-web", True, "Domain reputation and relations"),
        ("AlienVault OTX", "https://otx.alienvault.com/browse/global/indicator/domain/{q}", "public-web", True, "Threat intelligence"),
        ("URLhaus", "https://urlhaus.abuse.ch/browse.php?search={q}", "public-web", True, "Malware URL references"),
        ("ThreatFox", "https://threatfox.abuse.ch/browse.php?search={q}", "public-web", True, "IOC references"),
        ("NVD", "https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query={q}", "public-web", True, "Vulnerability references"),
        ("Shodan", "https://www.shodan.io/search?query=hostname%3A{q}", "login-dependent", True, "Internet-exposed asset search"),
    ],
    "breach_exposure": [
        ("Have I Been Pwned", "https://haveibeenpwned.com/DomainSearch", "login-dependent", False, "Domain exposure search"),
        ("Mozilla Monitor", "https://monitor.mozilla.org/", "public-web", False, "Exposure lookup"),
        ("IntelX", "https://intelx.io/", "login-dependent", False, "Search account/login may be required"),
        ("DeHashed", "https://www.dehashed.com/", "login-dependent", False, "Authorized exposure search"),
        ("Hudson Rock", "https://www.hudsonrock.com/", "public-web", False, "Cybercrime exposure intelligence"),
    ],
    "dark_web": [
        ("Ahmia", "https://ahmia.fi/search/?q={q}", "public-web", True, "Public onion-index search"),
        ("Tor Project", "https://www.torproject.org/", "public-web", False, "Tor ecosystem resources"),
        ("IntelX", "https://intelx.io/", "login-dependent", False, "Authorized dark-web intelligence"),
        ("Flashpoint", "https://flashpoint.io/", "login-dependent", False, "Commercial intelligence"),
        ("DarkOwl", "https://www.darkowl.com/", "login-dependent", False, "Commercial intelligence"),
    ],
    "geospatial": [
        ("OpenStreetMap", "https://www.openstreetmap.org/search?query={q}", "public-web", True, "Public map search"),
        ("Nominatim", "https://nominatim.openstreetmap.org/ui/search.html?q={q}", "public-web", True, "Geocoder search"),
        ("GeoNames", "https://www.geonames.org/search.html?q={q}", "public-web", True, "Geographic names"),
        ("IPinfo", "https://ipinfo.io/", "api-dependent", False, "IP geolocation / ASN"),
        ("Google Maps", "https://www.google.com/maps/search/{q}", "public-web", True, "Map context"),
    ],
    "financial_crypto": [
        ("Etherscan", "https://etherscan.io/search?f=0&q={q}", "public-web", True, "Public blockchain search"),
        ("Blockchair", "https://blockchair.com/search?q={q}", "public-web", True, "Public blockchain search"),
        ("SEC EDGAR", "https://www.sec.gov/edgar/search/#/q={q}", "public-web", True, "Public filings"),
        ("OpenCorporates", "https://opencorporates.com/companies?q={q}", "public-web", True, "Corporate records"),
        ("OFAC Sanctions", "https://sanctionssearch.ofac.treas.gov/", "public-web", False, "Use the official sanctions search"),
    ],
    "legal_public_records": [
        ("CourtListener", "https://www.courtlistener.com/?q={q}", "public-web", True, "Public court records"),
        ("RECAP Archive", "https://www.courtlistener.com/recap/", "public-web", False, "Public court documents"),
        ("SEC EDGAR", "https://www.sec.gov/edgar/search/#/q={q}", "public-web", True, "Public filings"),
        ("Companies House", "https://find-and-update.company-information.service.gov.uk/search/companies?q={q}", "public-web", True, "UK public company records"),
        ("OpenSanctions", "https://www.opensanctions.org/search/?q={q}", "public-web", True, "Public sanctions/entity records"),
        ("World Bank Debarred", "https://www.worldbank.org/en/projects-operations/procurement/debarred-firms", "public-web", False, "Official debarment list"),
    ],
}


def build_direct_links(domain: str) -> dict[str, list[dict]]:
    q = quote_plus(str(domain or '').strip())
    safe_domain = quote_plus(str(domain or '').strip())
    out: dict[str, list[dict]] = {}
    for category, rows in _TEMPLATES.items():
        links = []
        for i, (name, template, access, auto, note) in enumerate(rows, 1):
            # Templates use {q} and {domain}; both intentionally receive URL-encoded target text.
            url = template.format(q=q, domain=safe_domain)
            links.append(asdict(DirectLink(f"{category}.{i:02d}", category, name, url, access, auto, note)))
        out[category] = links
    return out
