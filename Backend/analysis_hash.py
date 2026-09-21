"""Hash investigation orchestrator.

Hash type identification is calculated locally. Reputation/detection data
comes only from configured external providers; a missing detection is never
invented.
"""
from . import providers
from .ioc_engine import hash_type
from .analysis_common import field


def analyze(digest: str) -> dict:
    digest = (digest or "").strip()
    htype = hash_type(digest)
    result = {
        "indicator": digest,
        "indicator_type": htype if htype != "UNKNOWN" else "HASH",
        "hash_type": field(htype, "CALCULATED", "local length/charset classification"),
        "valid": field(htype != "UNKNOWN", "CALCULATED", "local length/charset classification"),
        "threat_intelligence": [],
    }
    if htype == "UNKNOWN":
        result["error"] = ("Not a recognized MD5/SHA1/SHA256/SHA512 hex digest "
                           "(lengths 32/40/64/128).")
        return result
    result["threat_intelligence"] = providers.query_all("hash", digest.lower())
    return result
