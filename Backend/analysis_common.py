"""Shared helpers for the analysis orchestrators."""

_MULTI_LEVEL = {"co", "com", "net", "org", "gov", "ac", "edu", "mil"}


def registrable_domain(hostname: str) -> str:
    """Best-effort registrable (eTLD+1) domain from a hostname. CALCULATED."""
    h = (hostname or "").strip().lower().rstrip(".")
    if not h:
        return ""
    labels = h.split(".")
    if len(labels) <= 2:
        return h
    if labels[-2] in _MULTI_LEVEL and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def field(value, provenance: str, source: str = ""):
    """Wrap a single value with its provenance label."""
    return {"value": value, "provenance": provenance, "source": source}
