"""Generate samples/demo.apk for trying the Analysis Lab and Code Viewer."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

from builders import build_demo_apk  # noqa: E402

samples = ROOT / "samples"
samples.mkdir(exist_ok=True)
target = samples / "demo.apk"
target.write_bytes(build_demo_apk())
print(f"Wrote {target} ({target.stat().st_size} bytes)")
