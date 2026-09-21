"""Encoding / decoding utilities.

Every operation is explicitly labeled ENCODE or DECODE. Decoded content is
never characterized as malicious; if it merely resembles a command or
structured data we report the detected shape as an INFERRED observation and
keep it separate from any threat assessment.
"""
import base64
import binascii
import html
import json
import urllib.parse


class CodecError(ValueError):
    pass


def _b64_decode(data: str) -> str:
    pad = "=" * (-len(data) % 4)
    try:
        return base64.b64decode(data + pad, validate=True).decode("utf-8", errors="replace")
    except (binascii.Error, ValueError) as e:
        raise CodecError(f"Invalid Base64 input: {e}")


def _b64_encode(data: str) -> str:
    return base64.b64encode(data.encode("utf-8")).decode("ascii")


def _hex_decode(data: str) -> str:
    clean = data.replace(" ", "").replace("0x", "")
    try:
        return binascii.unhexlify(clean).decode("utf-8", errors="replace")
    except (binascii.Error, ValueError) as e:
        raise CodecError(f"Invalid hex input: {e}")


def _hex_encode(data: str) -> str:
    return binascii.hexlify(data.encode("utf-8")).decode("ascii")


def _binary_decode(data: str) -> str:
    bits = data.replace(" ", "")
    if not bits or len(bits) % 8 != 0 or set(bits) - {"0", "1"}:
        raise CodecError("Binary input must be a multiple of 8 bits of 0/1.")
    out = bytearray()
    for i in range(0, len(bits), 8):
        out.append(int(bits[i:i + 8], 2))
    return out.decode("utf-8", errors="replace")


def _binary_encode(data: str) -> str:
    return " ".join(format(b, "08b") for b in data.encode("utf-8"))


def _unicode_decode(data: str) -> str:
    try:
        return data.encode("utf-8").decode("unicode_escape")
    except (UnicodeDecodeError, UnicodeEncodeError, ValueError) as e:
        raise CodecError(f"Invalid unicode-escape input: {e}")


def _unicode_encode(data: str) -> str:
    return data.encode("unicode_escape").decode("ascii")


def _jwt_decode(token: str) -> dict:
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise CodecError("JWT must have three dot-separated segments.")
    decoded = {}
    for name, seg in (("header", parts[0]), ("payload", parts[1])):
        raw = _b64_decode(seg.replace("-", "+").replace("_", "/"))
        try:
            decoded[name] = json.loads(raw)
        except json.JSONDecodeError:
            decoded[name] = raw
    return decoded


SUPPORTED = [
    "base64", "url", "hex", "binary", "rot13", "html", "unicode", "jwt",
]


def run(operation: str, codec: str, data: str) -> dict:
    """operation: 'encode' | 'decode'. codec: one of SUPPORTED (jwt=decode only)."""
    operation = (operation or "").lower()
    codec = (codec or "").lower()
    if operation not in ("encode", "decode"):
        raise CodecError("operation must be 'encode' or 'decode'.")
    if codec not in SUPPORTED:
        raise CodecError(f"Unsupported codec '{codec}'. Supported: {', '.join(SUPPORTED)}")

    data = data or ""
    notes = []

    if codec == "jwt":
        if operation != "decode":
            raise CodecError("JWT supports decoding only (signature is NOT verified).")
        output = _jwt_decode(data)
        notes.append("Signature NOT verified; header/payload are base64url-decoded only.")
    elif codec == "base64":
        output = _b64_decode(data) if operation == "decode" else _b64_encode(data)
    elif codec == "url":
        output = urllib.parse.unquote_plus(data) if operation == "decode" else urllib.parse.quote(data, safe="")
    elif codec == "hex":
        output = _hex_decode(data) if operation == "decode" else _hex_encode(data)
    elif codec == "binary":
        output = _binary_decode(data) if operation == "decode" else _binary_encode(data)
    elif codec == "rot13":
        import codecs as _c
        output = _c.encode(data, "rot13")
    elif codec == "html":
        output = html.unescape(data) if operation == "decode" else html.escape(data)
    elif codec == "unicode":
        output = _unicode_decode(data) if operation == "decode" else _unicode_encode(data)
    else:
        raise CodecError("Unhandled codec.")

    result = {
        "operation": operation.upper(),
        "codec": codec,
        "input": data,
        "output": output,
        "provenance": "CALCULATED",
        "notes": notes,
    }
    if operation == "decode" and isinstance(output, str):
        shape = _describe_shape(output)
        if shape:
            result["decoded_shape"] = shape
            notes.append(
                "Decoded content shape is descriptive only; decoding is not a threat assessment."
            )
    return result


def _describe_shape(text: str) -> str:
    t = text.strip()
    if not t:
        return ""
    if t.startswith("{") or t.startswith("["):
        try:
            json.loads(t)
            return "JSON"
        except json.JSONDecodeError:
            pass
    if t.startswith(("cmd", "powershell", "bash", "sh ", "/bin/", "curl ", "wget ")):
        return "shell-command-like string"
    if "<script" in t.lower() or "http" in t.lower():
        return "contains URL/script-like content"
    if all(c.isprintable() or c in "\n\t" for c in t):
        return "printable text"
    return "non-printable/binary content"
