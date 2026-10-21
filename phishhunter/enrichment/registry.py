from phishhunter.config import settings
from phishhunter.enrichment.catalog import catalog
from phishhunter.enrichment.urlscan import URLScanConnector
from phishhunter.enrichment.virustotal import VirusTotalConnector


def available_connectors():
    items = []
    if settings.virustotal_api_key:
        items.append(VirusTotalConnector(settings.virustotal_api_key))
    if settings.urlscan_api_key:
        items.append(URLScanConnector(settings.urlscan_api_key))
    return items


def connector_catalog() -> list[dict[str, object]]:
    return catalog()
