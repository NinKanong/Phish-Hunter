from importlib import import_module
_MODULE='phishhunter.analyzers.file_analyzer'
_FUNCTION='analyze_file'
def _callable(): return getattr(import_module(_MODULE), _FUNCTION)
def analyze(target, *args, **kwargs): return _callable()(target, *args, **kwargs)
