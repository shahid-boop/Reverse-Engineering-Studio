from __future__ import annotations
import hashlib
import re
from pathlib import Path

def detect_format(data: bytes, filename: str = "") -> str:
    if data.startswith(b"MZ"): return "PE/DOS executable (signature only)"
    if data.startswith(b"\x7fELF"): return "ELF"
    if data.startswith((b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")): return "Mach-O"
    if data.startswith(b"PK\x03\x04"):
        return "Android APK/ZIP container" if Path(filename).suffix.lower() == ".apk" else "ZIP archive"
    if data.startswith(b"SQLite format 3\x00"): return "SQLite database"
    if data.startswith(b"%PDF-"): return "PDF document"
    if data.startswith(b"\x89PNG\r\n\x1a\n"): return "PNG image"
    if data.startswith(b"\xff\xd8\xff"): return "JPEG image"
    if data.lstrip().lower().startswith((b"<!doctype html", b"<html")): return "HTML document"
    return "Unknown / raw data"

def extract_strings(data: bytes, min_length: int = 5, limit: int = 80) -> list[str]:
    if min_length < 2 or limit < 1: raise ValueError("min_length must be >= 2 and limit must be >= 1")
    matches = re.findall(rb"[\x20-\x7e]{%d,}" % min_length, data)
    output, seen = [], set()
    for item in matches:
        value = item.decode("ascii", errors="replace").strip()
        if value and value not in seen:
            output.append(value[:300]); seen.add(value)
        if len(output) >= limit: break
    return output

def inspect_bytes(filename: str, data: bytes) -> dict:
    if not filename or not isinstance(data, bytes): raise ValueError("A filename and byte content are required.")
    return {
        "filename": Path(filename).name, "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "detected_format": detect_format(data, filename),
        "strings_preview": extract_strings(data),
        "warnings": ["Static metadata only: file content was not executed.",
                     "Format detection is heuristic and is not proof of file safety."]
    }
