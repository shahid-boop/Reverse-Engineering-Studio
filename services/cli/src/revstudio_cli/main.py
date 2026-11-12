import io
import json
import zipfile
from pathlib import Path

import typer
from rich import print

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

app = typer.Typer(help="Reverse Engineering Studio command line tools.")


def _is_apk(data: bytes, path: Path) -> bool:
    if path.suffix.lower() == ".apk":
        return True
    if data[:2] != b"PK":
        return False
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            return "AndroidManifest.xml" in archive.namelist()
    except (zipfile.BadZipFile, OSError, RuntimeError):
        return False


@app.command()
def inspect(path: Path):
    """Safely inspect file metadata without executing the file."""
    if not path.is_file():
        raise typer.BadParameter("Path must point to an existing file.")
    result = inspect_bytes(path.name, path.read_bytes())
    print(f"[bold cyan]Static inspection[/bold cyan] — {path.name}")
    print(json.dumps(result, indent=2))


@app.command()
def deep(path: Path):
    """Deep structural analysis for PE (exe/dll) and APK files."""
    if not path.is_file():
        raise typer.BadParameter("Path must point to an existing file.")
    data = path.read_bytes()
    if data[:2] == b"MZ":
        result = inspect_pe(path.name, data)
    elif _is_apk(data, path):
        result = inspect_apk(path.name, data)
    else:
        result = inspect_bytes(path.name, data)
        print("[yellow]Deep analysis covers PE and APK files; showing baseline inspection.[/yellow]")
    print(f"[bold cyan]Deep analysis[/bold cyan] — {path.name}")
    print(json.dumps(result, indent=2))


@app.command()
def code(
    path: Path,
    view: str = typer.Option("hex", help=f"One of: {', '.join(VIEWS)}"),
    target: str = typer.Option("", help="Section name, dex path or asset path"),
    offset: int = typer.Option(0, help="Byte or instruction offset"),
    limit: int = typer.Option(0, help="Max lines/instructions (0 = default)"),
):
    """View code and content: hex, strings, disasm, manifest, dex, asset."""
    if not path.is_file():
        raise typer.BadParameter("Path must point to an existing file.")
    result = code_view(
        path.name, path.read_bytes(),
        view=view,
        target=target or None,
        offset=offset,
        limit=limit or None,
    )
    print(f"[bold cyan]{view} view[/bold cyan] — {result['filename']}")
    print(result["content"])


@app.command()
def report(
    path: Path,
    out: str = typer.Option("", help="Write markdown or HTML report to this file (by extension)"),
    json_out: bool = typer.Option(False, "--json", help="Print full JSON report"),
):
    """Generate a scored evidence report (findings, risk, markdown, HTML)."""
    if not path.is_file():
        raise typer.BadParameter("Path must point to an existing file.")
    data = path.read_bytes()
    if data[:2] == b"MZ":
        analysis = inspect_pe(path.name, data)
    elif _is_apk(data, path):
        analysis = inspect_apk(path.name, data)
    else:
        analysis = inspect_bytes(path.name, data)
    rep = build_report(path.name, data, analysis)

    if json_out:
        print(json.dumps(rep, indent=2))
        return

    if out:
        target = Path(out)
        if target.suffix.lower() == ".html":
            target.write_text(rep["html"], encoding="utf-8")
        else:
            target.write_text(rep["markdown"], encoding="utf-8")
        print(f"[bold green]Report written[/bold green] — {target} "
              f"(risk {rep['risk']['level']} {rep['risk']['score']}/100, "
              f"{len(rep['findings'])} findings)")
        return

    risk = rep["risk"]
    print(f"[bold cyan]Evidence report[/bold cyan] — {rep['subject']['filename']}")
    print(f"Risk: [bold]{risk['level'].upper()}[/bold] {risk['score']}/100 · "
          f"{len(rep['findings'])} findings · report {rep['report_id']}")
    for f in rep["findings"]:
        color = {"critical": "red", "high": "red", "medium": "yellow",
                 "low": "cyan", "info": "white"}[f["severity"]]
        print(f"  [{color}]{f['severity'].upper():8}[/{color}] {f['id']} {f['title']}")
    print()
    print(rep["markdown"])


@app.command()
def decompile(
    path: Path,
    tool: str = typer.Option("jadx", help="jadx (Java source) or apktool (resources/smali)"),
    entry: str = typer.Option("", help="Class/file path inside the APK to print"),
    list_all: bool = typer.Option(False, "--list", help="List decompiled files only"),
):
    """Decompile an APK: JADX Java sources or APKTool resources/smali."""
    if not path.is_file():
        raise typer.BadParameter("Path must point to an existing file.")
    if tool not in ("jadx", "apktool"):
        raise typer.BadParameter("tool must be 'jadx' or 'apktool'.")
    data = path.read_bytes()
    try:
        if tool == "jadx":
            result = decompile_java(data, entry=entry or None)
            files = result["classes"]
            key = "source"
        else:
            result = decode_apktool(data, entry=entry or None)
            files = result["files"]
            key = "text"
    except ToolError as exc:
        print(f"[red]Tool error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    print(f"[bold cyan]{tool}[/bold cyan] — {path.name} · {result.get('classes_total') or result.get('files_total')} file(s)")
    if list_all or not entry:
        for name in files:
            print(f"  {name}")
    if entry:
        print(f"\n[bold]{entry}[/bold]\n")
        print(result.get(key) or "(no content)")


@app.command()
def tools():
    """Show installed external decompilers (JADX / APKTool / Java)."""
    status = tool_status()
    print("[bold cyan]External tools[/bold cyan]")
    print(f"  Java    : {status['java'] or 'NOT INSTALLED'}")
    print(f"  JADX    : {status['jadx'] or 'NOT INSTALLED'} {'✅' if status['jadx_ready'] else '❌'}")
    print(f"  APKTool : {status['apktool'] or 'NOT INSTALLED'} {'✅' if status['apktool_ready'] else '❌'}")


if __name__ == "__main__":
    app()
