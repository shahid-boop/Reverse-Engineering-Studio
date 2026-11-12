from __future__ import annotations

import hashlib
import io
import zipfile
from pathlib import Path

from revstudio_engine.axml import AxmlError, parse_axml
from revstudio_engine.dex import DexError, parse_dex

MAX_ENTRIES = 2000
MAX_DEX_FILES = 4
MAX_ASSETS = 1000
MAX_LIBS = 500


def _entry_info(info: zipfile.ZipInfo) -> dict:
    return {
        "name": info.filename,
        "size": info.file_size,
        "compressed_size": info.compress_size,
        "method": "stored" if info.compress_type == 0 else "deflate",
    }


def inspect_apk(filename: str, data: bytes) -> dict:
    if not filename or not isinstance(data, bytes):
        raise ValueError("A filename and byte content are required.")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise ValueError(f"Not a valid APK/ZIP container: {exc}") from exc

    with archive:
        entries: list[dict] = []
        entry_count = 0
        assets: list[dict] = []
        libs: list[dict] = []
        dex_infos: list[zipfile.ZipInfo] = []
        signatures: list[str] = []
        total_uncompressed = 0
        has_resources = False

        for info in archive.infolist():
            if info.is_dir():
                continue
            total_uncompressed += info.file_size
            entry_count += 1
            entry = _entry_info(info)
            if len(entries) < MAX_ENTRIES:
                entries.append(entry)
            lower = info.filename.lower()
            if info.filename.startswith("assets/"):
                if len(assets) < MAX_ASSETS:
                    assets.append(entry)
            elif info.filename.startswith("lib/") and lower.endswith(".so"):
                if len(libs) < MAX_LIBS:
                    libs.append(entry)
            elif lower.endswith(".dex") and len(dex_infos) < MAX_DEX_FILES:
                dex_infos.append(info)
            elif info.filename.startswith("META-INF/") and (
                lower.endswith((".rsa", ".dsa", ".ec", ".sf")) or lower.endswith("manifest.mf")
            ):
                signatures.append(info.filename)
            elif info.filename == "resources.arsc":
                has_resources = True

        manifest: dict = {"xml": None, "components": {}, "error": None}
        if "AndroidManifest.xml" in archive.namelist():
            try:
                manifest = parse_axml(archive.read("AndroidManifest.xml"))
            except (AxmlError, OSError, RuntimeError) as exc:
                manifest = {"xml": None, "components": {}, "error": str(exc)}

        dex_results: list[dict] = []
        for info in dex_infos:
            try:
                dex_results.append(parse_dex(archive.read(info), name=Path(info.filename).name))
            except (DexError, OSError, RuntimeError) as exc:
                dex_results.append({"name": info.filename, "error": str(exc)})

        components = manifest.get("components") or {}

    return {
        "filename": Path(filename).name,
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "format": "Android APK",
        "warnings": [
            "Static analysis only: the APK was not installed or executed.",
            "Manifest and DEX values are parsed structurally; treat them as evidence, not proof of runtime behavior.",
        ],
        "apk": {
            "package": components.get("package"),
            "version_name": components.get("version_name"),
            "version_code": components.get("version_code"),
            "min_sdk": components.get("min_sdk"),
            "target_sdk": components.get("target_sdk"),
            "compile_sdk": components.get("compile_sdk"),
            "application_label": components.get("application_label"),
            "application_icon": components.get("application_icon"),
            "launchable_activity": components.get("launchable_activity"),
            "permissions": components.get("permissions", []),
            "features": components.get("features", []),
            "activities": components.get("activities", []),
            "services": components.get("services", []),
            "receivers": components.get("receivers", []),
            "providers": components.get("providers", []),
            "instrumentations": components.get("instrumentations", []),
            "manifest_xml": manifest.get("xml"),
            "manifest_error": manifest.get("error"),
            "dex": dex_results,
            "entries_count": entry_count,
            "entries_truncated": len(entries) >= MAX_ENTRIES,
            "total_uncompressed_bytes": total_uncompressed,
            "entries": entries,
            "assets": assets,
            "native_libs": libs,
            "signatures": signatures,
            "has_resources_table": has_resources,
        },
    }
