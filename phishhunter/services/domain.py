"""Application service adapter for the Domain analyst.

The adapter is intentionally thin: parsing stays in the analyzer package,
normalization in the depth contract, and persistence in the web/API layer.
"""
from phishhunter.analysis.deep_enhance import enhance_result

SERVICE_KEY = 'domain'

def normalize(result: dict, target: str = "") -> dict:
    return enhance_result(result, SERVICE_KEY, target)
