from pathlib import Path
import json
from mcp.server.fastmcp import FastMCP
from revstudio_engine.static_inspector import inspect_bytes
mcp = FastMCP("Reverse Engineering Studio")
@mcp.tool()
def inspect_local_file(path: str) -> str:
    # Static, non-executing inspection; only analyze authorized files.
    target = Path(path).expanduser().resolve()
    if not target.is_file(): return json.dumps({"error":"File does not exist or is not a regular file."})
    try: return json.dumps(inspect_bytes(target.name, target.read_bytes()), indent=2)
    except OSError as exc: return json.dumps({"error":f"Could not read file: {exc}"})
@mcp.tool()
def list_capabilities() -> str:
    return json.dumps({
      "implemented":["static file metadata","SHA-256","basic signature detection","printable ASCII strings"],
      "planned":["PE/ELF/Mach-O deep analysis","APK manifest parsing","web bundle analysis","database inspection","evidence reports"],
      "safety":"Files are inspected as data and are never executed by this MCP server."
    }, indent=2)
def main(): mcp.run()
if __name__ == "__main__": main()
