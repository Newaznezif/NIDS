"""Google OIDC authentication (authorization-code flow).

Real OAuth only: the browser is redirected to Google, the returned code is
exchanged server-side, and the id_token signature is verified against Google's
published JWKS using a dependency-free RSASSA-PKCS1-v1_5 (SHA-256) check.
When credentials are absent every entry point reports NOT CONFIGURED instead of
pretending a login happened.
"""
import base64
import hashlib
import json
import logging
import time
import urllib.parse
import urllib.request

from . import config

logger = logging.getLogger("NIDS.GoogleOAuth")

AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
JWKS_URI = "https://www.googleapis.com/oauth2/v3/certs"
VALID_ISSUERS = {"accounts.google.com", "https://accounts.google.com"}

# ASN.1 DigestInfo prefix for SHA-256 in PKCS#1 v1.5 signatures.
_SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")

_jwks_cache = {"keys": {}, "expires": 0.0}


def configured() -> bool:
    return bool(config.GOOGLE_CLIENT_ID and config.GOOGLE_CLIENT_SECRET and config.GOOGLE_REDIRECT_URI)


def auth_url(state: str, nonce: str) -> str:
    params = {
        "client_id": config.GOOGLE_CLIENT_ID,
        "redirect_uri": config.GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "nonce": nonce,
        "prompt": "select_account",
    }
    return AUTH_ENDPOINT + "?" + urllib.parse.urlencode(params)


def _b64url_decode(segment: str) -> bytes:
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def _post_form(url: str, data: dict, timeout: float = 10.0) -> dict:
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def exchange_code(code: str) -> dict:
    return _post_form(TOKEN_ENDPOINT, {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": config.GOOGLE_CLIENT_ID,
        "client_secret": config.GOOGLE_CLIENT_SECRET,
        "redirect_uri": config.GOOGLE_REDIRECT_URI,
    })


def _fetch_jwks() -> dict:
    now = time.time()
    if _jwks_cache["expires"] > now and _jwks_cache["keys"]:
        return _jwks_cache["keys"]
    with urllib.request.urlopen(JWKS_URI, timeout=config.PROVIDER_TIMEOUT) as resp:
        doc = json.loads(resp.read().decode())
    keys = {k["kid"]: k for k in doc.get("keys", []) if k.get("kty") == "RSA"}
    _jwks_cache.update(keys=keys, expires=now + 3600)
    return keys


def _rsa_verify_sha256(signing_input: bytes, signature: bytes, jwk: dict) -> bool:
    n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
    e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
    s = int.from_bytes(signature, "big")
    if s >= n:
        return False
    k = (n.bit_length() + 7) // 8
    em = pow(s, e, n).to_bytes(k, "big")
    digest = hashlib.sha256(signing_input).digest()
    expected = b"\x00\x01" + b"\xff" * (k - len(_SHA256_DIGEST_INFO) - len(digest) - 3) \
        + b"\x00" + _SHA256_DIGEST_INFO + digest
    if len(expected) != k:
        return False
    diff = 0
    for a, b in zip(em, expected):
        diff |= a ^ b
    return diff == 0


def verify_id_token(id_token: str, nonce: str, now: float = None):
    """Return the verified claims dict, or raise ValueError with a safe reason."""
    now = time.time() if now is None else now
    try:
        header_b, payload_b, sig_b = id_token.split(".")
        header = json.loads(_b64url_decode(header_b))
        claims = json.loads(_b64url_decode(payload_b))
        signature = _b64url_decode(sig_b)
    except Exception as e:
        raise ValueError(f"Malformed id_token: {e}")
    if header.get("alg") != "RS256":
        raise ValueError(f"Unsupported id_token algorithm: {header.get('alg')}")
    if claims.get("iss") not in VALID_ISSUERS:
        raise ValueError("id_token issuer not trusted")
    if claims.get("aud") != config.GOOGLE_CLIENT_ID:
        raise ValueError("id_token audience mismatch")
    if int(claims.get("exp", 0)) <= now:
        raise ValueError("id_token expired")
    if nonce and claims.get("nonce") != nonce:
        raise ValueError("id_token nonce mismatch")
    jwk = _fetch_jwks().get(header.get("kid"))
    if not jwk:
        raise ValueError("No matching Google signing key")
    signing_input = (header_b + "." + payload_b).encode()
    if not _rsa_verify_sha256(signing_input, signature, jwk):
        raise ValueError("id_token signature verification failed")
    return claims


def profile_from_claims(claims: dict) -> dict:
    return {
        "sub": claims.get("sub", ""),
        "email": (claims.get("email") or "").lower(),
        "email_verified": bool(claims.get("email_verified")),
        "name": claims.get("name") or "",
    }
