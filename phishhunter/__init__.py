"""PhishGuard application package."""
from pathlib import Path
import sys

__version__ = "2.0.0"
_shared = Path(__file__).resolve().parents[1] / "libs" / "py-common"
if str(_shared) not in sys.path:
    sys.path.insert(0, str(_shared))
