from phishhunter.network_artifacts.reporting import json_report,csv_iocs,csv_events,stix_bundle,report_html

def export(result: dict, fmt: str):
    return {'json':(json_report(result),'application/json','json'),'ioc-csv':(csv_iocs(result),'text/csv','iocs.csv'),'events-csv':(csv_events(result),'text/csv','events.csv'),'stix':(stix_bundle(result),'application/json','stix.json'),'html':(report_html(result),'text/html','html')}[fmt]
