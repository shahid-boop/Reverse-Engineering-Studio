import json
from pathlib import Path
import typer
from rich import print
from revstudio_engine.static_inspector import inspect_bytes
app = typer.Typer(help="Reverse Engineering Studio command line tools.")
@app.command()
def inspect(path: Path):
    # Safely inspect file metadata without executing the file.
    if not path.is_file(): raise typer.BadParameter("Path must point to an existing file.")
    result = inspect_bytes(path.name, path.read_bytes())
    print(f"[bold cyan]Static inspection[/bold cyan] — {path.name}")
    print(json.dumps(result, indent=2))
if __name__ == "__main__": app()
