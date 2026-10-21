from importlib import import_module
_MODULE='phishhunter.analysis.deep_services'
_FUNCTION='deep_ip_analysis'
def _callable(): return getattr(import_module(_MODULE), _FUNCTION)
def analyze(target, *args, **kwargs): return _callable()(target, *args, **kwargs)
