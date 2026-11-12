from __future__ import annotations

import io
import zipfile
from pathlib import Path

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

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
from revstudio_engine.static_inspector import detect_format, inspect_bytes

router = APIRouter()

MAX_UPLOAD_BYTES = 100 * 1024 * 1024


def _check_size(content: bytes) -> None:
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File exceeds configured upload limit.")


def _zip_has_manifest(content: bytes) -> bool:
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            return "AndroidManifest.xml" in archive.namelist()
    except (zipfile.BadZipFile, OSError, RuntimeError):
        return False


@router.post("/deep")
async def deep_analyze(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(status_code=400, detail="A filename is required.")
    content = await file.read()
    _check_size(content)

    suffix = Path(file.filename).suffix.lower()
    head = content[:4]

    try:
        if head[:2] == b"MZ":
            return inspect_pe(file.filename, content)
        if suffix == ".apk" or (head[:2] == b"PK" and _zip_has_manifest(content)):
            return inspect_apk(file.filename, content)
        result = inspect_bytes(file.filename, content)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    result["deep_supported"] = False
    result["note"] = (
        f"Detected as '{result['detected_format']}'. Deep structural analysis "
        "currently covers PE (Windows) and APK (Android) files; showing baseline static inspection."
    )
    return result


@router.post("/report")
async def evidence_report(
    file: UploadFile = File(...),
    include_markdown: bool = Form(True),
    include_html: bool = Form(True),
):
    """Build a scored evidence report (JSON + Markdown + HTML) for a file."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="A filename is required.")
    content = await file.read()
    _check_size(content)

    suffix = Path(file.filename).suffix.lower()
    head = content[:2]

    try:
        if head == b"MZ":
            analysis = inspect_pe(file.filename, content)
        elif suffix == ".apk" or (head == b"PK" and _zip_has_manifest(content)):
            analysis = inspect_apk(file.filename, content)
        else:
            analysis = inspect_bytes(file.filename, content)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    report = build_report(file.filename, content, analysis)
    if not include_markdown:
        report.pop("markdown", None)
    if not include_html:
        report.pop("html", None)
    return report


@router.get("/tools")
def decompiler_tools():
    """Show which external decompilers (JADX / APKTool / Java) are installed."""
    return tool_status()


@router.post("/decompile")
async def decompile_endpoint(
    file: UploadFile = File(...),
    tool: str = Form("jadx"),
    entry: str | None = Form(None),
    filter: str | None = Form(None),
):
    """Decode/decompile an APK: tool=jadx (Java sources) or tool=apktool (resources/smali)."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="A filename is required.")
    if tool not in ("jadx", "apktool"):
        raise HTTPException(status_code=400, detail="tool must be 'jadx' or 'apktool'.")
    content = await file.read()
    _check_size(content)
    if not _zip_has_manifest(content):
        raise HTTPException(status_code=400, detail="Decompilation applies to APK files only.")

    try:
        if tool == "jadx":
            return decompile_java(content, class_filter=filter or None, entry=entry or None)
        return decode_apktool(content, entry=entry or None)
    except ToolError as exc:
        raise HTTPException(status_code=501, detail=str(exc)) from exc


@router.post("/code-view")
async def code_view_endpoint(
    file: UploadFile = File(...),
    view: str = Form("hex"),
    target: str | None = Form(None),
    offset: int = Form(0),
    limit: int | None = Form(None),
):
    if not file.filename:
        raise HTTPException(status_code=400, detail="A filename is required.")
    if view not in VIEWS:
        raise HTTPException(status_code=400, detail=f"Unknown view '{view}'.")
    content = await file.read()
    _check_size(content)

    try:
        return code_view(
            file.filename, content,
            view=view,
            target=target or None,
            offset=offset,
            limit=limit,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
