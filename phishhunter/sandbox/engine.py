from importlib import import_module

def engine(): return import_module("phishhunter.sandbox.manager").SandboxManager

def analyze(*args, **kwargs): raise RuntimeError("Sandbox is a provider boundary; use an isolated configured sandbox adapter.")
