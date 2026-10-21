from __future__ import annotations
CLOUDS={'amazon':'AWS','cloudfront':'AWS CloudFront','google':'Google Cloud','azure':'Microsoft Azure','cloudflare':'Cloudflare','fastly':'Fastly','akamai':'Akamai','digitalocean':'DigitalOcean','linode':'Linode','vultr':'Vultr','vercel':'Vercel','netlify':'Netlify'}

def detect(result:dict)->dict:
    text=' '.join([str(x.get('technology') or '')+' '+str(x.get('evidence') or '') for x in result.get('technology') or []]).lower()
    headers=' '.join([str(k)+' '+str(v) for k,v in (result.get('http',{}).get('headers') or {}).items()]).lower()
    text += ' '+headers
    hits=[]
    for marker,name in CLOUDS.items():
        if marker in text: hits.append({'provider':name,'marker':marker,'confidence':70,'evidence':'HTTP/technology observation'})
    seen=set(); out=[]
    for h in hits:
        if h['provider'] not in seen: seen.add(h['provider']); out.append(h)
    return {'status':'observed' if out else 'provider-dependent','providers':out}
