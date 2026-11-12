from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

try:
    import pefile
except ImportError:  # pragma: no cover
    pefile = None

MACHINE_TYPES = {
    0x014C: "i386",
    0x0200: "IA64",
    0x8664: "AMD64",
    0x01C0: "ARM",
    0x01C4: "ARM Thumb-2",
    0x8C41: "ARMv7",
    0xAA64: "ARM64",
    0x5032: "RISCV32",
    0x5064: "RISCV64",
}

SUBSYSTEMS = {
    0: "UNKNOWN", 1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI",
    5: "OS2_CUI", 7: "POSIX_CUI", 9: "WINDOWS_CE_GUI",
    10: "EFI_APPLICATION", 11: "EFI_BOOT_SERVICE_DRIVER",
    12: "EFI_RUNTIME_DRIVER", 13: "EFI_ROM", 14: "XBOX",
    16: "WINDOWS_BOOT_APPLICATION",
}

RESOURCE_TYPES = {
    1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG",
    6: "STRING", 7: "FONTDIR", 8: "FONT", 9: "ACCELERATOR",
    10: "RCDATA", 11: "MESSAGETABLE", 12: "GROUP_CURSOR",
    14: "GROUP_ICON", 16: "VERSION", 17: "DLGINCLUDE",
    19: "PLUGPLAY", 20: "VXD", 21: "ANICURSOR", 22: "ANICON",
    23: "HTML", 24: "MANIFEST",
}

SECTION_FLAG_NAMES = (
    (0x00000020, "CODE"),
    (0x00000040, "DATA"),
    (0x00000080, "BSS"),
    (0x20000000, "EXEC"),
    (0x40000000, "READ"),
    (0x80000000, "WRITE"),
)

MAX_FUNCTIONS_PER_DLL = 500
MAX_RESOURCES = 500
MAX_EXPORTS = 2000


def _decode(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _section_flags(chars: int) -> list[str]:
    return [name for bit, name in SECTION_FLAG_NAMES if chars & bit]


def _timestamp(epoch: int) -> str | None:
    if not epoch:
        return None
    try:
        return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _clr_runtime_version(pe) -> str | None:
    try:
        com = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
        if not com.VirtualAddress or not com.Size:
            return None
        root = pe.get_data(com.VirtualAddress, min(com.Size, 4096))
        if root[:4] != b"BSJB":
            return None
        version_len = int.from_bytes(root[12:16], "little")
        raw = root[16:16 + version_len]
        return raw.split(b"\x00", 1)[0].decode("ascii", errors="replace") or None
    except Exception:
        return None


def _collect_resources(pe) -> tuple[list[dict], dict]:
    entries: list[dict] = []
    counts: dict[str, int] = {}
    directory = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if directory is None:
        return entries, counts

    def walk(node, path: list[str], depth: int) -> None:
        if len(entries) >= MAX_RESOURCES or depth > 4:
            return
        for entry in node.entries:
            if isinstance(entry.struct, str) or getattr(entry.struct, "Name", None) is not None:
                name = _decode(entry.struct.Name) if not isinstance(entry.struct, str) else entry.struct
                label = str(name)
            else:
                label = str(entry.struct.Id)
            new_path = path + [label]
            if hasattr(entry, "directory"):
                walk(entry.directory, new_path, depth + 1)
            else:
                rva = entry.data.struct.OffsetToData
                size = entry.data.struct.Size
                leaf_type = new_path[0] if new_path else "?"
                counts[leaf_type] = counts.get(leaf_type, 0) + 1
                entries.append({
                    "type": leaf_type,
                    "path": new_path,
                    "rva": rva,
                    "size": size,
                })

    try:
        walk(directory, [], 0)
    except Exception:
        return entries, counts
    return entries, counts


def _version_info(pe) -> dict:
    info: dict[str, str] = {}
    try:
        for fileinfo in getattr(pe, "FileInfo", []) or []:
            for table in getattr(fileinfo, "StringTable", []) or []:
                for key, value in table.entries.items():
                    info[_decode(key)] = _decode(value)
    except Exception:
        pass
    return info


def inspect_pe(filename: str, data: bytes) -> dict:
    if pefile is None:
        raise ValueError("The 'pefile' package is not installed; run: pip install pefile")
    if not filename or not isinstance(data, bytes):
        raise ValueError("A filename and byte content are required.")

    try:
        pe = pefile.PE(data=data, fast_load=False)
    except Exception as exc:
        raise ValueError(f"PE parsing failed: {exc}") from exc

    try:
        return _summarize_pe(filename, data, pe)
    finally:
        pe.close()


def _summarize_pe(filename: str, data: bytes, pe) -> dict:
    import hashlib

    file_header = pe.FILE_HEADER
    optional = pe.OPTIONAL_HEADER
    bits = 64 if optional.Magic == 0x20B else 32
    machine = MACHINE_TYPES.get(file_header.Machine, f"0x{file_header.Machine:04X}")
    entry_rva = optional.AddressOfEntryPoint
    image_base = optional.ImageBase

    entry_section = None
    sections = []
    packing_reasons: list[str] = []
    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
        entropy = section.get_entropy()
        flags = _section_flags(section.Characteristics)
        sections.append({
            "name": name,
            "virtual_address": section.VirtualAddress,
            "virtual_size": section.Misc_VirtualSize,
            "raw_size": section.SizeOfRawData,
            "entropy": round(entropy, 3),
            "characteristics": flags,
        })
        if section.contains_rva(entry_rva):
            entry_section = name
        upper = name.upper()
        if upper.startswith(("UPX", ".UPX", ".PETITE", ".ASPACK", ".MPRESS")):
            packing_reasons.append(f"Suspicious section name: {name}")
        if entropy >= 7.4 and section.Misc_VirtualSize > 0:
            packing_reasons.append(f"Very high entropy in {name}: {entropy:.2f}")

    imports = []
    truncated_imports = False
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll = _decode(entry.dll)
        functions = []
        for imp in entry.imports:
            if len(functions) >= MAX_FUNCTIONS_PER_DLL:
                truncated_imports = True
                break
            if imp.name:
                functions.append(_decode(imp.name))
            else:
                functions.append(f"#{imp.ordinal}")
        imports.append({"dll": dll, "function_count": len(entry.imports), "functions": functions})

    exports = []
    export_dir = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if export_dir is not None:
        for exp in export_dir.symbols:
            if len(exports) >= MAX_EXPORTS:
                break
            exports.append({
                "name": _decode(exp.name) or f"#{exp.ordinal}",
                "ordinal": exp.ordinal,
                "rva": exp.address,
            })

    resource_entries, resource_counts = _collect_resources(pe)
    version_info = _version_info(pe)

    data_directories = []
    directory_names = [
        "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC",
        "DEBUG", "ARCHITECTURE", "GLOBALPTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT",
        "IAT", "DELAY_IMPORT", "COM_DESCRIPTOR", "RESERVED",
    ]
    for idx, name in enumerate(directory_names):
        try:
            entry = optional.DATA_DIRECTORY[idx]
        except Exception:
            continue
        if entry.VirtualAddress or entry.Size:
            data_directories.append({
                "name": name,
                "rva": entry.VirtualAddress,
                "size": entry.Size,
                "file_offset": entry.VirtualAddress if name == "SECURITY" else None,
            })

    debug_info = []
    for debug in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []) or []:
        record = {"type": str(debug.struct.Type)}
        try:
            if debug.entry:
                pdb = _decode(getattr(debug.entry, "PDBFileName", None))
                if pdb:
                    record["pdb"] = pdb
                timestamp = getattr(debug.entry, "TimeDateStamp", None)
                if timestamp:
                    record["timestamp"] = _timestamp(timestamp)
        except Exception:
            pass
        debug_info.append(record)

    overlay_offset = None
    try:
        overlay_offset = pe.get_overlay_data_start_offset()
    except Exception:
        overlay_offset = None
    overlay_size = (len(data) - overlay_offset) if overlay_offset else 0

    security = optional.DATA_DIRECTORY[4]
    signed = bool(security.Size)

    com_descriptor = optional.DATA_DIRECTORY[14]
    is_dotnet = bool(com_descriptor.VirtualAddress and com_descriptor.Size)
    clr_version = _clr_runtime_version(pe) if is_dotnet else None

    tls_present = bool(optional.DATA_DIRECTORY[9].Size)
    reloc_size = optional.DATA_DIRECTORY[5].Size
    bound_import_size = optional.DATA_DIRECTORY[11].Size

    if entry_rva and not any(
        section.VirtualAddress <= entry_rva < section.VirtualAddress + max(section.Misc_VirtualSize, section.SizeOfRawData)
        for section in pe.sections
    ):
        packing_reasons.append("Entry point lies outside all sections")
    if len(imports) <= 1 and bits == 64 and any(s["entropy"] > 7.0 for s in sections):
        packing_reasons.append("Very few imports combined with high-entropy sections")

    warnings = [
        "Static analysis only: the executable was not run.",
        "Structural facts come from the PE headers; heuristics may produce false positives.",
    ]

    return {
        "filename": Path(filename).name,
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "format": "PE32+" if bits == 64 else "PE32",
        "warnings": warnings,
        "pe": {
            "machine": machine,
            "bits": bits,
            "is_dll": bool(file_header.Characteristics & 0x2000),
            "is_exe": not bool(file_header.Characteristics & 0x2000),
            "subsystem": SUBSYSTEMS.get(optional.Subsystem, str(optional.Subsystem)),
            "compile_time": _timestamp(file_header.TimeDateStamp),
            "entry_point_rva": entry_rva,
            "entry_point_section": entry_section,
            "image_base": image_base,
            "linker_version": f"{optional.MajorLinkerVersion}.{optional.MinorLinkerVersion}",
            "os_version": f"{optional.MajorOperatingSystemVersion}.{optional.MinorOperatingSystemVersion}",
            "is_dotnet": is_dotnet,
            "clr_runtime_version": clr_version,
            "authenticode_signed": signed,
            "authenticode_size": security.Size,
            "overlay_size": overlay_size,
            "tls_directory": tls_present,
            "relocation_size": reloc_size,
            "bound_import_size": bound_import_size,
            "sections": sections,
            "imports": imports,
            "imports_truncated": truncated_imports,
            "exports": exports,
            "resource_counts": resource_counts,
            "resources": resource_entries,
            "resources_truncated": len(resource_entries) >= MAX_RESOURCES,
            "version_info": version_info,
            "debug": debug_info,
            "data_directories": data_directories,
            "packing_suspected": bool(packing_reasons),
            "packing_reasons": packing_reasons,
        },
    }
