"""External decompiler integration: JADX (DEX -> Java) and APKTool (resources/smali).

Both tools run as subprocesses against a temp copy of the uploaded file.
Nothing is executed from the analyzed file itself; timeouts and output caps
keep a hostile input from wedging the API.

Tool layout (resolved relative to the repository root, then REVSTUDIO_TOOLS):

    tools/
      jre21/           portable JRE (bin/java.exe)
      jadx/            jadx zip extracted (bin/jadx.bat, lib/)
      apktool.jar      APKTool jar
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

# How long a single decompile may run before we kill it.
TOOL_TIMEOUT_SECONDS = int(os.environ.get("REVSTUDIO_TOOL_TIMEOUT", "120"))
# Hard cap on returned source size (characters).
MAX_SOURCE_CHARS = 400_000
MAX_LISTING_ENTRIES = 4000

_REPO_ROOT = Path(__file__).resolve().parents[4]
_TOOLS_ENV = os.environ.get("REVSTUDIO_TOOLS", "")
_ROOTS = [p for p in (Path(_TOOLS_ENV) if _TOOLS_ENV else None, _REPO_ROOT / "tools") if p]


def _find(*candidates: str) -> Path | None:
    for root in _ROOTS:
        for rel in candidates:
            path = root / rel
            if path.exists():
                return path
    return None


def find_java() -> Path | None:
    exe = _find(Path("jre21") / "bin" / "java.exe", Path("jdk") / "bin" / "java.exe")
    if exe:
        return exe
    return shutil.which("java")


def find_jadx() -> Path | None:
    # jadx zip layout: bin/jadx (or jadx.bat) + lib/jadx-*.jar
    bat = _find(Path("jadx") / "bin" / "jadx.bat", Path("jadx") / "bin" / "jadx")
    if bat:
        return bat
    # fall back to running the jar directly
    java = find_java()
    jar = _find(Path("jadx") / "lib")  # directory; pick the jar below
    if java and jar:
        jars = sorted(jar.glob("jadx*.jar"))
        if jars:
            return jars[-1]
    return None


def find_apktool() -> Path | None:
    return _find("apktool.jar", "apktool_3.0.3.jar")


def tool_status() -> dict:
    """Report which external tools are installed for the UI / MCP."""
    java = find_java()
    jadx = find_jadx()
    apktool = find_apktool()
    jadx_ok = bool(java and jadx)
    # jadx provided as jar needs java; as script needs java too
    return {
        "java": str(java) if java else None,
        "jadx": str(jadx) if jadx else None,
        "jadx_ready": jadx_ok,
        "apktool": str(apktool) if apktool else None,
        "apktool_ready": bool(java and apktool),
        "timeout_seconds": TOOL_TIMEOUT_SECONDS,
    }


class ToolError(RuntimeError):
    """Raised when an external tool fails or is unavailable."""


def _run(cmd: list[str], timeout: int = TOOL_TIMEOUT_SECONDS) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired as exc:
        raise ToolError(f"Tool timed out after {timeout}s: {' '.join(cmd[:3])}") from exc
    except OSError as exc:
        raise ToolError(f"Could not launch tool: {exc}") from exc


def _jadx_cmd(apk_path: Path, out_dir: Path) -> list[str]:
    java = find_java()
    jadx = find_jadx()
    if not java or not jadx:
        raise ToolError("JADX is not installed. Extract jadx into tools/jadx and a JRE into tools/jre21.")
    if jadx.suffix == ".jar":
        return [str(java), "-jar", str(jadx), "--no-res", "-d", str(out_dir), str(apk_path)]
    return [str(jadx), "--no-res", "-d", str(out_dir), str(apk_path)]


def decompile_java(apk_bytes: bytes, class_filter: str | None = None,
                   entry: str | None = None) -> dict:
    """Decompile an APK's DEX to Java sources with JADX.

    Returns:
      {"classes": [relative java paths...], "source": str|None, "tool": "jadx", ...}
    - If *entry* is given, `source` holds that file's content (fuzzy path match).
    - If *class_filter* is given, only matching class names are listed.
    """
    status = tool_status()
    if not status["jadx_ready"]:
        raise ToolError(
            "JADX is not available. Install a JRE (tools/jre21) and jadx (tools/jadx)."
        )

    with tempfile.TemporaryDirectory(prefix="revstudio-jadx-") as tmp:
        tmp_path = Path(tmp)
        apk_path = tmp_path / "input.apk"
        apk_path.write_bytes(apk_bytes)
        out_dir = tmp_path / "out"
        out_dir.mkdir()

        result = _run(_jadx_cmd(apk_path, out_dir))
        if not out_dir.exists() or not any(out_dir.rglob("*.java")):
            detail = (result.stderr or result.stdout or "").strip()[-1200:]
            raise ToolError(f"JADX produced no Java output. {detail}")

        sources = sorted(p for p in out_dir.rglob("*.java") if p.is_file())
        listing = [str(p.relative_to(out_dir)).replace("\\", "/") for p in sources]
        if class_filter:
            needle = class_filter.lower()
            listing = [x for x in listing if needle in x.lower()]

        source_text: str | None = None
        if entry:
            needle = entry.lower().replace("\\", "/")
            match = next((p for p in sources
                          if needle in str(p.relative_to(out_dir)).replace("\\", "/").lower()), None)
            if match is None:
                # last resort: match on class name inside file content
                match = next((p for p in sources if needle in p.read_text(
                    encoding="utf-8", errors="replace").lower()[:4000]), None)
            if match is None:
                raise ToolError(f"No decompiled source matches '{entry}'.")
            source_text = match.read_text(encoding="utf-8", errors="replace")

        return {
            "tool": "jadx",
            "classes": listing[:MAX_LISTING_ENTRIES],
            "classes_total": len(listing),
            "truncated": len(listing) > MAX_LISTING_ENTRIES,
            "source": source_text[:MAX_SOURCE_CHARS] if source_text else None,
            "source_truncated": bool(source_text and len(source_text) > MAX_SOURCE_CHARS),
            "stderr_tail": (result.stderr or "").strip()[-800:] or None,
        }


def decode_apktool(apk_bytes: bytes, entry: str | None = None) -> dict:
    """Decode an APK with APKTool (resources, manifest XML, smali, original files).

    With *entry*, returns that decoded file's text (e.g. 'AndroidManifest.xml',
    'res/layout/main.xml', 'smali/com/demo/MainActivity.smali').
    """
    status = tool_status()
    if not status["apktool_ready"]:
        raise ToolError(
            "APKTool is not available. Place apktool.jar in tools/ and a JRE in tools/jre21."
        )
    java = find_java()
    apktool = find_apktool()

    with tempfile.TemporaryDirectory(prefix="revstudio-apktool-") as tmp:
        tmp_path = Path(tmp)
        apk_path = tmp_path / "input.apk"
        apk_path.write_bytes(apk_bytes)
        out_dir = tmp_path / "decoded"
        out_dir.mkdir()

        result = _run([str(java), "-jar", str(apktool), "d", "-f", "-o", str(out_dir),
                       str(apk_path)])
        if not out_dir.exists():
            detail = (result.stderr or result.stdout or "").strip()[-1200:]
            raise ToolError(f"APKTool decoding failed. {detail}")

        files = sorted(p for p in out_dir.rglob("*") if p.is_file())
        listing = [str(p.relative_to(out_dir)).replace("\\", "/") for p in files]

        text: str | None = None
        if entry:
            needle = entry.lower().replace("\\", "/")
            match = next((p for p in files
                          if needle in str(p.relative_to(out_dir)).replace("\\", "/").lower()), None)
            if match is None:
                raise ToolError(f"No decoded file matches '{entry}'.")
            text = match.read_text(encoding="utf-8", errors="replace")

        return {
            "tool": "apktool",
            "files": listing[:MAX_LISTING_ENTRIES],
            "files_total": len(listing),
            "truncated": len(listing) > MAX_LISTING_ENTRIES,
            "text": text[:MAX_SOURCE_CHARS] if text else None,
            "text_truncated": bool(text and len(text) > MAX_SOURCE_CHARS),
            "stderr_tail": (result.stderr or "").strip()[-800:] or None,
        }


def is_apk(data: bytes, filename: str = "") -> bool:
    if filename.lower().endswith(".apk"):
        return True
    if data[:2] != b"PK":
        return False
    try:
        with zipfile.ZipFile(__import__("io").BytesIO(data)) as zf:
            return "AndroidManifest.xml" in zf.namelist()
    except (zipfile.BadZipFile, OSError, RuntimeError):
        return False
