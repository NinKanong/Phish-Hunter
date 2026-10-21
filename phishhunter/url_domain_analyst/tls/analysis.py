from __future__ import annotations

def analyze(tls:dict|None, ct:dict|None=None) -> dict:
    tls=tls or {}; ct=ct or {}
    version=str(tls.get('tls_version') or '')
    weak=version in {'TLSv1','TLSv1.0','TLSv1.1','SSLv3'}
    return {'status':tls.get('status'),'peer_ip':tls.get('peer_ip'),'tls_version':version,'cipher':tls.get('cipher'),
            'issuer':tls.get('issuer'),'subject':tls.get('subject'),'san':tls.get('san') or [],
            'sha256_fingerprint':tls.get('sha256_fingerprint'),'weak_protocol':weak,
            'certificate_expired':tls.get('expired'),'hostname_match':tls.get('hostname_match'),
            'alpn':tls.get('alpn'),'ocsp_stapling':tls.get('ocsp_stapling'),'ct_presence':bool(ct.get('certificates')),
            'posture':'review' if weak or tls.get('expired') is True else 'normal'}
