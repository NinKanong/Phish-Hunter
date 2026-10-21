from importlib import import_module
_MODULE='phishhunter.analysis.graph_builder'
_FUNCTION='build_graph'
def _callable(): return getattr(import_module(_MODULE), _FUNCTION)
def analyze(target, *args, **kwargs): return _callable()(target, *args, **kwargs)
