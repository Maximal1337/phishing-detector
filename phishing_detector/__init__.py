"""Rule-based email phishing detector (Python standard library only)."""

from .models import Indicator, Result
from .parser import parse
from .scoring import analyze

__all__ = ["Indicator", "Result", "analyze", "parse"]
