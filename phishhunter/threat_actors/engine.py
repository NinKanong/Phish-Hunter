from importlib import import_module
_MODULE='phishhunter.services.actors'
_FUNCTION='normalize'
def _callable(): return getattr(import_module(_MODULE), _FUNCTION)
def analyze(target, *args, **kwargs): return _callable()(target, *args, **kwargs)
