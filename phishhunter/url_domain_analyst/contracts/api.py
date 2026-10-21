from __future__ import annotations

ENDPOINTS={
    'analyze_url':'/analyze/url','analyze_domain':'/analyze/domain','analyze_batch':'/analyze/batch','scan':'/scan/{id}',
    'results':'/scan/{id}/results','graph':'/scan/{id}/graph','domain':'/domain/{domain}','url':'/url/{url}',
    'certificate':'/cert/{fingerprint}','ip':'/ip/{ip}','asn':'/asn/{asn}','whois':'/whois/{domain}','dns':'/dns/{domain}',
    'pdns':'/pdns/{domain}','screenshot':'/screenshot/{url}','diff':'/diff','monitor':'/monitor','watchlist':'/watchlist'
}

def api_manifest()->dict: return {'rest':ENDPOINTS,'graphql':True,'websocket':['/ws/scan/{id}','/ws/monitor/{domain}','/ws/alerts'],'webhooks':True,'bulk':True}
