from importlib import import_module
_MODULE='phishhunter.analyzers.email_deep_engine'
_FUNCTION='analyze_email_deep'
def _callable(): return getattr(import_module(_MODULE), _FUNCTION)
def analyze(target, *args, **kwargs): return _callable()(target, *args, **kwargs)
