"""Utility functions for path normalization and joining."""
import re

_PATH_RE = re.compile(r"^(?:[A-Za-z0-9._-]+)(?:/[A-Za-z0-9._-]+)*$")

def normalize_path(p: str) -> str:
    """Trim, drop trailing '/', validate allowed segments; raise ValueError if invalid."""
    p = p.strip().rstrip("/")
    if not _PATH_RE.fullmatch(p):
        raise ValueError("invalid path")
    return p

def join_paths(*parts: str) -> str:
    """Join segments with '/', normalizing duplicates and trimming slashes."""
    cleaned = [s.strip("/ ") for s in parts if s and s.strip("/ ")]
    return "/".join(cleaned)
