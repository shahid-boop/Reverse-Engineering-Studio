import io
import json
import zipfile
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from revstudio_engine.apk_inspector import inspect_apk
from revstudio_engine.code_view import VIEWS, code_view
from revstudio_engine.decompiler import (
    ToolError,
    decode_apktool,
    decompile_java,
    tool_status,
)
from revstudio_engine.evidence_report import build_report
from revstudio_engine.pe_inspector import inspect_pe
from revstudio_engine.static_inspector import inspect_bytes

mcp = FastMCP("Reverse Engineering Studio")


def _read_authorized(path: str):
    target = Path(path).expanduser().resolve()
    if not target.is_file():
        return None, json.dumps({"error": "File does not exist or is not a regular file."})
    try:
        return (target, target.read_bytes()), None
    except OSError as exc:
        return None, json.dumps({"error": f"Could not read file: {exc}"})


def _is_apk(data: bytes, target: Path) -> bool:
    if target.suffix.lower() == ".apk":
        return True
    if data[:2] != b"PK":
        return False
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            return "AndroidManifest.xml" in archive.namelist()
    except (zipfile.BadZipFile, OSError, RuntimeError):
        return False


@mcp.tool()
def inspect_local_file(path: str) -> str:
    """Static, non-executing inspection: metadata, SHA-256, signature, strings."""
    loaded, error = _read_authorized(path)
    if error:
        return error
    target, data = loaded
    try:
        return json.dumps(inspect_bytes(target.name, data), indent=2)
    except (ValueError, OSError) as exc:
        return json.dumps({"error": str(exc)})


@mcp.tool()
def analyze_deep_file(path: str) -> str:
    """Deep structural analysis: PE headers/sections/imports/resources, or APK manifest/DEX/assets."""
    loaded, error = _read_authorized(path)
    if error:
        return error
    target, data = loaded
    try:
        if data[:2] == b"MZ":
            result = inspect_pe(target.name, data)
        elif _is_apk(data, target):
            result = inspect_apk(target.name, data)
        else:
            result = inspect_bytes(target.name, data)
            result["note"] = "Deep analysis covers PE and APK files; baseline inspection shown."
        return json.dumps(result, indent=2)
    except (ValueError, OSError) as exc:
        return json.dumps({"error": str(exc)})


@mcp.tool()
def view_file_code(path: str, view: str = "hex", target: str = "", offset: int = 0, limit: int = 0) -> str:
    """View file content: hex, strings, disasm (PE), manifest/dex/asset (APK).

    Views: hex, strings, disasm, manifest, dex, asset, targets.
    """
    loaded, error = _read_authorized(path)
    if error:
        return error
    target_file, data = loaded
    try:
        result = code_view(
            target_file.name, data,
            view=view,
            target=target or None,
            offset=offset,
            limit=limit or None,
        )
        return json.dumps(result, indent=2)
    except (ValueError, OSError) as exc:
        return json.dumps({"error": str(exc)})


@mcp.tool()
def generate_evidence_report(path: str) -> str:
    """Scored evidence report: risk level, findings with evidence, markdown + HTML renderings."""
    loaded, error = _read_authorized(path)
    if error:
        return error
    target, data = loaded
    try:
        if data[:2] == b"MZ":
            analysis = inspect_pe(target.name, data)
        elif _is_apk(data, target):
            analysis = inspect_apk(target.name, data)
        else:
            analysis = inspect_bytes(target.name, data)
        return json.dumps(build_report(target.name, data, analysis), indent=2)
    except (ValueError, OSError) as exc:
        return json.dumps({"error": str(exc)})


@mcp.tool()
def decompile_apk(path: str, tool: str = "jadx", entry: str = "") -> str:
    """Decompile an APK: tool='jadx' returns Java sources, tool='apktool' returns decoded
    resources/smali. Pass entry (e.g. 'MainActivity.java' or 'AndroidManifest.xml') to get
    that file's content; omit it to list decompiled files."""
    loaded, error = _read_authorized(path)
    if error:
        return error
    target, data = loaded
    try:
        if tool == "jadx":
            result = decompile_java(data, entry=entry or None)
        elif tool == "apktool":
            result = decode_apktool(data, entry=entry or None)
        else:
            return json.dumps({"error": "tool must be 'jadx' or 'apktool'."})
        return json.dumps(result, indent=2)
    except ToolError as exc:
        return json.dumps({"error": str(exc)})
    except (ValueError, OSError) as exc:
        return json.dumps({"error": str(exc)})


@mcp.tool()
def list_capabilities() -> str:
    return json.dumps({
        "implemented": [
            "static file metadata", "SHA-256", "basic signature detection", "printable strings",
            "deep PE analysis (sections, imports, exports, resources, version info, packing heuristics)",
            "deep APK analysis (manifest decode, permissions, components, DEX classes, assets)",
            "code views: hex dump, strings, x86/x64 disassembly, manifest XML, DEX outline, APK assets",
            "evidence reports: scored findings with evidence, Markdown + HTML export",
            "decompilation: JADX Java sources, APKTool resources/smali (external tools)",
        ],
        "planned": ["Ghidra-backed decompilation", "AI provider routing"],
        "external_tools": tool_status(),
        "safety": "Files are inspected as data and are never executed by this MCP server.",
    }, indent=2)


def main():
    mcp.run()


if __name__ == "__main__":
    main()
