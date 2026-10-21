from __future__ import annotations
from enum import StrEnum

class EvidenceKind(StrEnum):
    OBSERVED = 'observed'
    CORRELATED = 'correlated'
    INFERRED = 'inferred'
    VERIFY = 'requires-verification'

class NodeKind(StrEnum):
    TARGET='target'; URL='url'; DOMAIN='domain'; SUBDOMAIN='subdomain'; IP='ip'; ASN='asn'
    NETBLOCK='netblock'; CERT='certificate'; ISSUER='certificate_issuer'; REGISTRAR='registrar'
    ORG='organization'; EMAIL='email'; PHONE='phone'; NS='nameserver'; MX='mailserver'
    TXT='txt_record'; TECHNOLOGY='technology'; CDN='cdn'; WAF='waf'; SCREENSHOT='screenshot'
    HTML='html_document'; JS='js_bundle'; COOKIE='cookie'; HEADER='header'; BRAND='brand'; KIT='phishing_kit'
    IOC='ioc'; FEED='feed'; BLOCKLIST='blocklist'; CAMPAIGN='campaign'; ACTOR='threat_actor'; CASE='case'
    REDIRECT='redirect'; PATH='path'; QUERY='query'; PORT='port'; SERVICE='service'; HOSTING='hosting'

class EdgeKind(StrEnum):
    RESOLVES_TO='RESOLVES_TO'; CNAME_TO='CNAME_TO'; REDIRECTS_TO='REDIRECTS_TO'; LOADS='LOADS'; EMBEDS='EMBEDS'
    ISSUED='ISSUED'; ISSUED_FOR='ISSUED_FOR'; SIGNED_BY='SIGNED_BY'; REGISTERED_BY='REGISTERED_BY'
    MANAGED_BY='MANAGED_BY'; NS_OF='NS_OF'; MX_OF='MX_OF'; SAME_AS='SAME_AS'; LOOKS_LIKE='LOOKS_LIKE'
    IMPERSONATES='IMPERSONATES'; SHARES_CERT='SHARES_CERT'; SHARES_IP='SHARES_IP'; SHARES_ASN='SHARES_ASN'
    SHARES_FAVICON='SHARES_FAVICON'; HAS_TECH='HAS_TECH'; HAS_PORT='HAS_PORT'; RUNS='RUNS'; LOCATED_AT='LOCATED_AT'
    FLAGGED_BY='FLAGGED_BY'; INDICATES='INDICATES'; PART_OF='PART_OF'; SUPPORTS='SUPPORTS'; OBSERVED_IN='OBSERVED_IN'
