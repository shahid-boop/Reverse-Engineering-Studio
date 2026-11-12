from __future__ import annotations

import io
import re
import zipfile
from pathlib import Path

from revstudio_engine.axml import AxmlError, parse_axml
from revstudio_engine.dex import DexError, parse_dex

MAX_TEXT_BYTES = 262_144  # 256 KB of text per response
MAX_HEX_BYTES = 65_536
MAX_INSTRUCTIONS = 500
MAX_STRINGS = 500

VIEWS = ("targets", "hex", "strings", "disasm", "manifest", "dex", "asset")


def _hex_dump(data: bytes, offset: int, length: int) -> str:
    chunk = data[offset:offset + length]
    lines = []
    for i in range(0, len(chunk), 16):
        row = chunk[i:i + 16]
        hex_part = " ".join(f"{byte:02x}" for byte in row).ljust(47)
        text = "".join(chr(byte) if 0x20 <= byte <= 0x7E else "." for byte in row)
        lines.append(f"{offset + i:08x}  {hex_part} |{text}|")
    return "\n".join(lines)


def _strings_with_offsets(data: bytes, min_length: int, limit: int) -> str:
    lines = []
    seen = set()
    for match in re.finditer(rb"[\x20-\x7e]{%d,}" % min_length, data):
        value = match.group().decode("ascii", errors="replace")
        if value in seen:
            continue
        seen.add(value)
        lines.append(f"{match.start():08x}  {value[:300]}")
        if len(lines) >= limit:
            break
    return "\n".join(lines)


def _disassemble(code: bytes, base_address: int, bits: int, limit: int) -> tuple[str, str | None]:
    try:
        import capstone
    except ImportError:
        return "", "The 'capstone' package is not installed; run: pip install capstone"

    mode = capstone.CS_MODE_64 if bits == 64 else capstone.CS_MODE_32
    md = capstone.Cs(capstone.CS_ARCH_X86, mode)
    lines = []
    count = 0
    for instruction in md.disasm(code, base_address):
        if count >= limit:
            break
        operands = instruction.op_str
        line = f"0x{instruction.address:08x}  {instruction.mnemonic:<8} {operands}".rstrip()
        lines.append(line)
        count += 1
    if not lines:
        return "(no instructions decoded)", None
    return "\n".join(lines), None


def _open_apk(data: bytes) -> zipfile.ZipFile:
    try:
        return zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise ValueError(f"Not a valid APK/ZIP container: {exc}") from exc


def _pe_section(data: bytes, target: str | None) -> tuple[bytes, str, int, int]:
    try:
        import pefile
    except ImportError:
        raise ValueError("The 'pefile' package is not installed; run: pip install pefile") from None
    try:
        pe = pefile.PE(data=data, fast_load=False)
    except Exception as exc:
        raise ValueError(f"PE parsing failed: {exc}") from exc
    try:
        chosen = None
        for section in pe.sections:
            name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
            if target and name == target:
                chosen = section
                break
        if chosen is None:
            for section in pe.sections:
                if section.Characteristics & 0x20000000:
                    chosen = section
                    break
        if chosen is None and pe.sections:
            chosen = pe.sections[0]
        if chosen is None:
            raise ValueError("The PE file has no sections to disassemble.")
        raw = pe.get_data(chosen.VirtualAddress, chosen.SizeOfRawData)
        base = pe.OPTIONAL_HEADER.ImageBase + chosen.VirtualAddress
        bits = 64 if pe.OPTIONAL_HEADER.Magic == 0x20B else 32
        name = chosen.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
        return raw, name, base, bits
    finally:
        pe.close()


def _dex_outline(dex: dict) -> str:
    lines = [
        f"DEX {dex.get('name')}  (version {dex.get('dex_version')})",
        "counts: " + ", ".join(f"{k}={v}" for k, v in (dex.get("counts") or {}).items()),
        "",
    ]
    for cls in dex.get("classes", []):
        header = f"class {cls['name']}"
        if cls.get("superclass"):
            header += f" extends {cls['superclass']}"
        if cls.get("access"):
            header += f"  [{cls['access']}]"
        lines.append(header)
        for method in cls.get("methods", []):
            lines.append(f"    {method['access']} {method['name']}{method['proto']}  ({method['kind']})")
        lines.append("")
    return "\n".join(lines)


def available_targets(filename: str, data: bytes) -> list[dict]:
    targets: list[dict] = []
    suffix = Path(filename).suffix.lower()
    head = data[:4]

    if head[:2] == b"MZ" or suffix in (".exe", ".dll", ".sys", ".scr"):
        try:
            import pefile
            pe = pefile.PE(data=data, fast_load=True)
            try:
                for section in pe.sections:
                    name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
                    targets.append({
                        "id": name,
                        "label": f"section {name} ({section.SizeOfRawData} bytes)",
                        "kind": "section",
                    })
            finally:
                pe.close()
        except Exception:
            pass
        targets.append({"id": "", "label": "default executable section", "kind": "section"})

    if head[:2] == b"PK" or suffix == ".apk":
        try:
            archive = _open_apk(data)
        except ValueError:
            archive = None
        if archive is not None:
            with archive:
                names = archive.namelist()
                if "AndroidManifest.xml" in names:
                    targets.append({"id": "AndroidManifest.xml", "label": "AndroidManifest.xml", "kind": "manifest"})
                for name in names:
                    if name.lower().endswith(".dex"):
                        targets.append({"id": name, "label": name, "kind": "dex"})
                for name in names:
                    if name.startswith("assets/") and not name.endswith("/"):
                        targets.append({"id": name, "label": name, "kind": "asset"})

    return targets


def code_view(filename: str, data: bytes, view: str, target: str | None = None,
              offset: int = 0, limit: int | None = None) -> dict:
    if not filename or not isinstance(data, bytes):
        raise ValueError("A filename and byte content are required.")
    if view not in VIEWS:
        raise ValueError(f"Unknown view '{view}'. Choose one of: {', '.join(VIEWS)}.")

    warnings = ["Static analysis only: content is displayed as data and never executed."]
    meta: dict = {}
    truncated = False
    content = ""

    if view == "targets":
        content = ""
        meta["targets"] = available_targets(filename, data)

    elif view == "hex":
        offset = max(0, int(offset))
        length = min(int(limit) if limit else 4096, MAX_HEX_BYTES)
        content = _hex_dump(data, offset, length)
        meta.update({"offset": offset, "length": length, "file_size": len(data)})
        truncated = offset + length < len(data)

    elif view == "strings":
        min_length = 4
        max_results = min(int(limit) if limit else MAX_STRINGS, MAX_STRINGS)
        content = _strings_with_offsets(data, min_length, max_results)
        meta.update({"min_length": min_length, "limit": max_results, "file_size": len(data)})
        truncated = content.count("\n") + 1 >= max_results

    elif view == "disasm":
        section, section_name, base, bits = _pe_section(data, target or None)
        start = max(0, int(offset))
        instruction_limit = min(int(limit) if limit else MAX_INSTRUCTIONS, MAX_INSTRUCTIONS)
        code = section[start:start + min(instruction_limit * 16, 65536)]
        content, error = _disassemble(code, base + start, bits, instruction_limit)
        if error:
            raise ValueError(error)
        meta.update({
            "section": section_name,
            "base_address": hex(base),
            "bits": bits,
            "byte_offset": start,
            "instructions": content.count("\n") + 1,
        })
        truncated = start + len(code) < len(section)

    elif view == "manifest":
        archive = _open_apk(data)
        with archive:
            if "AndroidManifest.xml" not in archive.namelist():
                raise ValueError("This archive has no AndroidManifest.xml.")
            try:
                decoded = parse_axml(archive.read("AndroidManifest.xml"))
            except AxmlError as exc:
                raise ValueError(f"Manifest decode failed: {exc}") from exc
        content = decoded["xml"]
        meta["components"] = decoded["components"]
        meta["string_count"] = decoded["string_count"]

    elif view == "dex":
        archive = _open_apk(data)
        with archive:
            dex_names = [n for n in archive.namelist() if n.lower().endswith(".dex")]
            chosen = target if target in dex_names else (dex_names[0] if dex_names else None)
            if not chosen:
                raise ValueError("This APK contains no .dex files.")
            try:
                dex = parse_dex(archive.read(chosen), name=Path(chosen).name)
            except DexError as exc:
                raise ValueError(str(exc)) from exc
        content = _dex_outline(dex)
        meta.update({"dex": chosen, "counts": dex["counts"], "classes": len(dex["classes"])})
        truncated = bool(dex.get("classes_truncated"))

    elif view == "asset":
        if not target:
            raise ValueError("An asset path target is required for the asset view.")
        archive = _open_apk(data)
        with archive:
            names = archive.namelist()
            if target not in names:
                raise ValueError(f"Asset not found: {target}")
            raw = archive.read(target)
        if len(raw) > MAX_TEXT_BYTES:
            raw = raw[:MAX_TEXT_BYTES]
            truncated = True
        text = raw.decode("utf-8", errors="replace")
        if "\ufffd" in text:
            warnings.append("Some bytes were not valid UTF-8; replacement characters were shown.")
        content = text
        meta.update({"asset": target, "bytes": len(raw)})

    return {
        "view": view,
        "filename": Path(filename).name,
        "target": target,
        "content": content,
        "line_count": content.count("\n") + 1 if content else 0,
        "truncated": truncated,
        "meta": meta,
        "warnings": warnings,
    }
