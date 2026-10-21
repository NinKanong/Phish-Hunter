from __future__ import annotations
from typing import Any

# Conservative fallback. Optional PSL libraries can be used by deployments, while this
# table covers common multi-label/public/private suffix families without pretending to
# have a complete live PSL snapshot.
MULTI_LABEL_SUFFIXES={
 'co.uk','org.uk','ac.uk','gov.uk','com.au','net.au','org.au','com.br','com.cn','com.hk','com.sg',
 'co.jp','ne.jp','or.jp','co.nz','org.nz','co.kr','co.in','firm.in','net.in','org.in','gen.in','ind.in',
 'com.mx','com.tr','com.tw','com.ar','com.pl','com.ua','com.my','com.ph','co.za','co.th','com.vn','com.ng',
}
PRIVATE_SUFFIXES={'github.io','gitlab.io','pages.dev','vercel.app','netlify.app','herokuapp.com','s3.amazonaws.com','cloudfront.net','azurewebsites.net','appspot.com'}


def split_registered_domain(domain: str) -> dict[str, Any]:
    labels=[x for x in str(domain or '').strip('.').lower().split('.') if x]
    if not labels: return {'fqdn':'','registered_domain':'','suffix':'','sld':'','subdomains':[],'method':'empty'}
    if len(labels)==1: return {'fqdn':labels[0],'registered_domain':labels[0],'suffix':labels[0],'sld':labels[0],'subdomains':[],'method':'single-label'}
    suffix='.'.join(labels[-2:])
    method='last-two-label-fallback'
    if suffix in MULTI_LABEL_SUFFIXES or suffix in PRIVATE_SUFFIXES:
        suffix='.'.join(labels[-2:])
        reg='.'.join(labels[-3:]) if len(labels)>=3 else '.'.join(labels)
        sub=labels[:-3]
        sld=labels[-3] if len(labels)>=3 else labels[0]
        return {'fqdn':'.'.join(labels),'registered_domain':reg,'suffix':suffix,'sld':sld,'subdomains':sub,'method':'curated-public-private-suffix'}
    reg='.'.join(labels[-2:])
    return {'fqdn':'.'.join(labels),'registered_domain':reg,'suffix':labels[-1],'sld':labels[-2],'subdomains':labels[:-2],'method':method}


def try_psl(domain: str) -> dict[str,Any]:
    """Use an installed Public Suffix List library when deployment provides one."""
    try:
        import tldextract  # optional production dependency
        e=tldextract.extract(str(domain or '').strip('.').lower())
        reg='.'.join(x for x in (e.domain,e.suffix) if x)
        return {'registered_domain':reg,'suffix':e.suffix,'sld':e.domain,'subdomains':e.subdomain.split('.') if e.subdomain else [],'method':'tldextract'}
    except Exception:
        return split_registered_domain(domain)
