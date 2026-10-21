from .engine import analyze
from .manifest import manifest

def run(target, *args, **kwargs): return analyze(target, *args, **kwargs)
def capabilities(): return manifest()
