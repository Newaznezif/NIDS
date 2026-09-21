"""File analysis: safe upload handling + local static analysis.

All hashes, entropy, strings and PE/ELF structure are computed locally from
the uploaded bytes (provenance CALCULATED / EXTRACTED). Files are NEVER sent
to external services automatically; external submission requires explicit
analyst action and configured providers.
"""
import hashlib
import math
import os
import re
import struct
import uuid
from collections import Counter

from . import config

_HASH_CHUNK = 1024 * 1024
_STRINGS_RE = re.compile(rb"[\x20-\x7e]{6,}")

PE_MACHINES = {0x14c: "x86 (i386)", 0x8664: "x64 (AMD64)", 0x1c0: "ARM", 0xaa64: "ARM64", 0x200: "IA-64"}
ELF_MACHINES = {0x03: "x86", 0x3e: "x86-64", 0x28: "ARM", 0xb7: "AArch64", 0x08: "MIPS"}
ELF_TYPES = {1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}


def secure_filename_local(name: str) -> str:
    """Strip path components and dangerous characters (path-traversal guard)."""
    base = os.path.basename((name or "").replace("\\", "/"))
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", base).strip("._")
    return cleaned[:120] or "upload"


def stored_name_for(original: str) -> str:
    ext = os.path.splitext(original)[1].lower()
    return f"{uuid.uuid4().hex}{ext}"


def allowed_extension(original: str) -> bool:
    return os.path.splitext(original or "")[1].lower() in config.ALLOWED_UPLOAD_EXTENSIONS


def compute_hashes(path: str) -> dict:
    h = {"md5": hashlib.md5(), "sha1": hashlib.sha1(),
         "sha256": hashlib.sha256(), "sha512": hashlib.sha512()}
    size = 0
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(_HASH_CHUNK)
            if not chunk:
                break
            size += len(chunk)
            for dig in h.values():
                dig.update(chunk)
    return {k: v.hexdigest() for k, v in h.items()} | {"size": size}


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def extract_strings(data: bytes, limit: int = 200, minlen: int = 6):
    found = _STRINGS_RE.findall(data)
    return [s.decode("ascii") for s in found[:limit]]


def detect_kind(data: bytes, original_name: str = "") -> str:
    if data[:2] == b"MZ":
        return "PE"
    if data[:4] == b"\x7fELF":
        return "ELF"
    if data[:4] == b"%PDF":
        return "PDF"
    if data[:2] == b"PK":
        return "ZIP/ARCHIVE"
    if data[:2] == b"\x1f\x8b":
        return "GZIP"
    if data[:2] in (b"#!",) or original_name.lower().endswith((".py", ".ps1", ".bat", ".sh", ".js", ".vbs")):
        return "SCRIPT"
    if data[:1] == b"{":
        return "JSON"
    return "UNKNOWN"


def _rva_to_offset(rva: int, sections) -> int:
    for name, vaddr, vsize, rawptr, rawsize in sections:
        if vaddr <= rva < vaddr + max(vsize, rawsize):
            return rva - vaddr + rawptr
    return -1


def pe_metadata(data: bytes) -> dict:
    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            return {"error": "Not a valid PE image"}
        coff = e_lfanew + 4
        machine, nsec, timestamp, _ps, _pn, size_opt, _chars = struct.unpack_from("<HHIIIHH", data, coff)
        opt = coff + 20
        magic = struct.unpack_from("<H", data, opt)[0]
        pe32plus = magic == 0x20B
        subsystem = struct.unpack_from("<H", data, opt + 68)[0]
        dd_off = opt + (112 if pe32plus else 96)
        import_rva, import_size = struct.unpack_from("<II", data, dd_off + 8)

        sec_off = opt + size_opt
        sections = []
        for i in range(nsec):
            off = sec_off + i * 40
            name = data[off:off + 8].rstrip(b"\0").decode("ascii", errors="replace")
            vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, off + 8)
            sections.append((name, vaddr, vsize, rawptr, rawsize))

        section_info = []
        for name, vaddr, vsize, rawptr, rawsize in sections:
            blob = data[rawptr:rawptr + rawsize]
            section_info.append({
                "name": name,
                "virtual_size": vsize,
                "raw_size": rawsize,
                "entropy": round(shannon_entropy(blob), 3),
            })

        imports = []
        if import_rva and import_size:
            io = _rva_to_offset(import_rva, sections)
            if io >= 0:
                pos = io
                while pos + 20 <= len(data):
                    oft, _ts, _fc, name_rva, _ft = struct.unpack_from("<IIIII", data, pos)
                    if name_rva == 0 and oft == 0:
                        break
                    no = _rva_to_offset(name_rva, sections)
                    if no >= 0:
                        end = data.index(b"\0", no) if b"\0" in data[no:no + 64] else no + 64
                        imports.append(data[no:end].decode("ascii", errors="replace"))
                    pos += 20

        return {
            "format": "PE32+" if pe32plus else "PE32",
            "machine": PE_MACHINES.get(machine, hex(machine)),
            "section_count": nsec,
            "compile_timestamp": timestamp,
            "subsystem": {2: "GUI", 3: "Console", 1: "Native"}.get(subsystem, subsystem),
            "sections": section_info,
            "imports": imports[:50],
            "provenance": "EXTRACTED",
            "source": "local PE header parse",
        }
    except Exception as e:
        return {"error": f"PE parse failed: {type(e).__name__}: {e}"}


def elf_metadata(data: bytes) -> dict:
    try:
        is64 = data[4] == 2
        endian = "<" if data[5] == 1 else ">"
        e_type, e_machine = struct.unpack_from(endian + "HH", data, 16)
        entry = struct.unpack_from(endian + ("Q" if is64 else "I"), data, 24)[0]
        shoff = struct.unpack_from(endian + ("Q" if is64 else "I"), data, 32 if is64 else 32)[0]
        shnum_idx = 58 if is64 else 46
        shnum = struct.unpack_from(endian + "H", data, shnum_idx)[0]
        phnum = struct.unpack_from(endian + "H", data, shnum_idx - 2)[0]
        return {
            "format": "ELF64" if is64 else "ELF32",
            "endian": "little" if endian == "<" else "big",
            "type": ELF_TYPES.get(e_type, e_type),
            "machine": ELF_MACHINES.get(e_machine, hex(e_machine)),
            "entry_point": hex(entry),
            "section_header_count": shnum,
            "program_header_count": phnum,
            "provenance": "EXTRACTED",
            "source": "local ELF header parse",
        }
    except Exception as e:
        return {"error": f"ELF parse failed: {type(e).__name__}: {e}"}


def analyze_file(path: str, original_name: str = "") -> dict:
    with open(path, "rb") as fh:
        data = fh.read(config.MAX_UPLOAD_BYTES)
    hashes = compute_hashes(path)
    kind = detect_kind(data, original_name)
    result = {
        "original_name": original_name,
        "size": hashes["size"],
        "md5": hashes["md5"],
        "sha1": hashes["sha1"],
        "sha256": hashes["sha256"],
        "sha512": hashes["sha512"],
        "hash_provenance": "CALCULATED",
        "hash_source": "computed locally from uploaded bytes",
        "kind": kind,
        "entropy": round(shannon_entropy(data), 3),
        "entropy_provenance": "CALCULATED",
        "strings": extract_strings(data),
        "strings_provenance": "EXTRACTED",
        "external_submission": "NOT PERFORMED (requires explicit analyst action)",
    }
    if kind == "PE":
        result["structure"] = pe_metadata(data)
    elif kind == "ELF":
        result["structure"] = elf_metadata(data)
    else:
        result["structure"] = {"note": f"No structural parser for kind {kind}.",
                               "provenance": "UNAVAILABLE"}
    return result
