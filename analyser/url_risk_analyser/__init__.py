"""URL risk analyser: separates confirmed-malicious threat-intel matches from heuristic risk indicators."""

from .analyser import analyse

__all__ = ["analyse"]
__version__ = "1.0.0"
