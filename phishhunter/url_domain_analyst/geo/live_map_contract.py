from __future__ import annotations
from pathlib import Path
import json, math

_DATA=Path(__file__).with_name('country_centers.json')
try:
    COUNTRY_INDEX=json.loads(_DATA.read_text(encoding='utf-8'))
except Exception:
    COUNTRY_INDEX={}


def _point_id(p:dict, i:int)->str:
    return str(p.get('id') or p.get('ip') or p.get('name') or f'point-{i}')


def _valid_point(p:dict)->bool:
    try:
        lat=float(p.get('lat')); lon=float(p.get('lon'))
        return -90<=lat<=90 and -180<=lon<=180
    except (TypeError,ValueError):
        return False


def build(geo:dict|None, branches:dict|None=None)->dict:
    g=geo if isinstance(geo,dict) else {}; b=branches if isinstance(branches,dict) else {}
    points=[p for p in (g.get('map_points') or []) if isinstance(p,dict) and _valid_point(p)]
    branches_rows=[p for p in (b.get('locations') or []) if isinstance(p,dict) and _valid_point(p)]
    country_layers=[x for x in (g.get('country_layers') or []) if isinstance(x,dict)]
    # Arcs are rendered only between two separately observed geographic entities. We never
    # infer a network route or physical connection from geographic proximity.
    geographic_entities=[]
    for i,p in enumerate(points): geographic_entities.append({'id':_point_id(p,i),'type':'network','lat':float(p['lat']),'lon':float(p['lon']),'label':p.get('city') or p.get('ip') or 'network','source':p.get('source')})
    offset=len(geographic_entities)
    for j,p in enumerate(branches_rows): geographic_entities.append({'id':_point_id(p,offset+j),'type':'corporate','lat':float(p['lat']),'lon':float(p['lon']),'label':p.get('name') or p.get('city') or 'company location','source':p.get('source')})
    arcs=[]
    for i in range(len(geographic_entities)-1):
        a,bv=geographic_entities[i],geographic_entities[i+1]
        if a.get('source') and bv.get('source') and a['source']!=bv['source']:
            arcs.append({'source':a['id'],'target':bv['id'],'relation':'multi-source-geographic-correlation','evidence':'both endpoints independently observed; not a physical route'})
    return {
      'mode':'dominus-global-live-map-v29',
      'projection':'equirectangular-2d + orthographic-3d globe texture',
      'geometry_asset':'/static/url_domain/world.svg',
      'country_layers':country_layers,
      'network_points':points,
      'corporate_locations':branches_rows,
      'geographic_entities':geographic_entities,
      'geographic_arcs':arcs,
      'country_index':COUNTRY_INDEX,
      'country_count':len(COUNTRY_INDEX),
      'controls':['3d-real-globe','2d-world','drag-rotate','wheel-zoom','hover-live-object','click-live-object','fit-world','search-global','fullscreen','layer-menu','reset-rotation'],
      'marker_types':['datacenter','edge-pop','origin','anycast','bulletproof','threat-zone','historical','cluster','company-hq','company-office','company-dc','company-subsidiary','cert-issuer','registrar','custom'],
      'layers':['earth','earthquakes','flights','grid'],
      'live_feeds':[{'id':'usgs-earthquakes','name':'USGS Earthquakes','kind':'public-realtime','url':'https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/all_day.geojson','refresh_seconds':60},{'id':'opensky-aircraft','name':'OpenSky Aircraft','kind':'public-realtime','url':'https://opensky-network.org/api/states/all','refresh_seconds':60}],
      'interaction_contract':{'live_object_click':'show lightweight live-object metadata','globe_drag':'rotate world','wheel_zoom':'zoom world','search':'find loaded live objects','layer_toggle':'show or hide live layers'},
      'evidence_policy':'Global live feeds are rendered only from returned provider observations. Country centroids are visualization anchors only and are never represented as exact host coordinates.',
      'fallback_policy':'The globe uses bundled world geometry and a local texture renderer. No remote tile, CDN or map API is required for the base visualization.',
      'privacy_policy':'No private home address, precise personal location or inferred employee location is plotted. Public corporate locations require source evidence.',
    }
