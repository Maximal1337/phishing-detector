"""Rule-based email phishing detector (Python standard library only)."""

from .models import Indicator, Result
from .parser import parse

__all__ = ["Indicator", "Result", "parse"]
