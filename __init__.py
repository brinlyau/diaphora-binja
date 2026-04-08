import os, sys, importlib.util

# Ensure repo root is importable so `import diaphora`, `diaphora_binja`, etc. resolve.
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.insert(0, _here)

# The package directory is named 'diaphora', which shadows diaphora.py (the core
# engine) when code does `import diaphora`.  Load diaphora.py explicitly and
# merge its public symbols into this package so that `diaphora.CBinDiff` etc.
# resolve correctly for diaphora_binja.py and other importers.
_core_path = os.path.join(_here, "diaphora.py")
_spec = importlib.util.spec_from_file_location("diaphora._engine", _core_path)
_core = importlib.util.module_from_spec(_spec)
sys.modules["diaphora._engine"] = _core
_spec.loader.exec_module(_core)
globals().update({k: v for k, v in vars(_core).items() if not k.startswith("__")})

from plugin import binja_plugin  # noqa: F401
