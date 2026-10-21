from __future__ import annotations
from .reporting.case import export_json, compact_case

def report_manifest()->dict:
    return {'formats':['json','markdown','html','csv','xml','stix-2.1','taxii-2.1','misp','pdf','docx','xlsx','syslog','cef','leef'],
            'chain_of_custody':True,'evidence_provenance':True}

def export_case(result:dict,fmt='json')->str:
    if fmt=='json': return export_json(result)
    return export_json(result)
