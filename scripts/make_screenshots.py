"""Capture README screenshots of the web UI using headless Chrome (CDP).

Launches Chrome with remote debugging, drives each page (nav clicks + file
injection via fetch), and saves viewport PNGs into docs/screenshots/.

Usage:  .venv/Scripts/python.exe scripts/make_screenshots.py
"""
from __future__ import annotations

import asyncio
import base64
import json
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

import websockets

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "screenshots"
PORT = 9333
BASE = "http://localhost:5173"

CHROME_CANDIDATES = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
]


def find_chrome() -> str:
    for path in CHROME_CANDIDATES:
        if Path(path).exists():
            return path
    sys.exit("No Chrome/Edge found")


def wait_ready(url: str, timeout: float = 30.0) -> dict:
    import time
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                return json.loads(resp.read())
        except Exception:
            time.sleep(0.3)
    raise RuntimeError("Chrome DevTools endpoint did not come up")


class CDP:
    def __init__(self, ws_url: str):
        self.ws_url = ws_url
        self._id = 0

    async def __aenter__(self):
        self.conn = await websockets.connect(self.ws_url, max_size=64 * 1024 * 1024)
        return self

    async def __aexit__(self, *exc):
        await self.conn.close()

    async def send(self, method: str, params: dict | None = None) -> dict:
        self._id += 1
        msg_id = self._id
        await self.conn.send(json.dumps({"id": msg_id, "method": method, "params": params or {}}))
        while True:
            raw = await asyncio.wait_for(self.conn.recv(), timeout=60)
            data = json.loads(raw)
            if data.get("id") == msg_id:
                if "error" in data:
                    raise RuntimeError(f"{method}: {data['error']}")
                return data.get("result", {})

    async def eval_js(self, expression: str) -> dict:
        return await self.send("Runtime.evaluate", {
            "expression": expression, "returnByValue": True, "awaitPromise": True,
        })

    async def navigate(self, url: str) -> None:
        await self.send("Page.navigate", {"url": url})
        await asyncio.sleep(1.2)

    async def wait_text(self, text: str, timeout: float = 15.0) -> bool:
        import time
        deadline = time.time() + timeout
        while time.time() < deadline:
            res = await self.eval_js(
                f"document.body.innerText.includes({json.dumps(text)})"
            )
            if res.get("result", {}).get("value"):
                return True
            await asyncio.sleep(0.3)
        return False

    async def shot(self, name: str) -> None:
        res = await self.send("Page.captureScreenshot", {"format": "png"})
        (OUT / name).write_bytes(base64.b64decode(res["data"]))
        print(f"  saved {name}")


# JS helpers injected into pages -------------------------------------------

CLICK_NAV = "(label) => { const l=[...document.querySelectorAll('nav a')].find(a=>a.textContent.includes(label)); if(l){l.click(); return true;} return false; }"

INJECT_FILE = r"""async (name) => {
  const res = await fetch('/' + name);
  const blob = await res.blob();
  const file = new File([blob], name, { type: 'application/octet-stream' });
  const input = document.querySelector('input[type=file]');
  if (!input) return 'no-input';
  const dt = new DataTransfer();
  dt.items.add(file);
  input.files = dt.files;
  input.dispatchEvent(new Event('change', { bubbles: true }));
  return 'ok';
}"""

CLICK_BUTTON = "(label) => { const b=[...document.querySelectorAll('button')].find(x=>x.textContent.trim().includes(label) && !x.disabled); if(b){b.click(); return true;} return false; }"


async def capture(cdp: CDP, name: str) -> None:
    await asyncio.sleep(0.4)
    await cdp.shot(name)


async def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    chrome = find_chrome()
    profile = ROOT / ".chrome-shot-profile"
    if profile.exists():
        shutil.rmtree(profile, ignore_errors=True)

    proc = subprocess.Popen([
        chrome, "--headless=new", f"--remote-debugging-port={PORT}",
        f"--user-data-dir={profile}", "--window-size=1440,900",
        "--no-first-run", "--disable-gpu", "--hide-scrollbars",
        "about:blank",
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    try:
        targets = wait_ready(f"http://127.0.0.1:{PORT}/json/list")
        page = next(t for t in targets if t["type"] == "page")
        async with CDP(page["webSocketDebuggerUrl"]) as cdp:
            await cdp.send("Page.enable")
            await cdp.send("Runtime.enable")
            await cdp.send("Emulation.setDeviceMetricsOverride",
                           {"width": 1440, "height": 900, "deviceScaleFactor": 1, "mobile": False})

            # 1. Overview
            print("[1/6] Overview")
            await cdp.navigate(BASE)
            await cdp.wait_text("REVERSE ENGINEERING WORKSPACE")
            await capture(cdp, "01-overview.png")

            # 2. Analysis lab — inject demo.apk and run deep analysis
            print("[2/6] Analysis lab")
            await cdp.eval_js(f"({CLICK_NAV})('Analysis lab')")
            await cdp.wait_text("Deep structural")
            print("   inject:", (await cdp.eval_js(f"({INJECT_FILE})('demo.apk')"))["result"]["value"])
            await asyncio.sleep(0.5)
            await cdp.eval_js(f"({CLICK_BUTTON})('Run analysis')")
            await cdp.wait_text("DEEP ANALYSIS RESULT", timeout=30)
            await asyncio.sleep(0.6)
            await capture(cdp, "02-analysis-lab.png")

            # 3. Code viewer — inject and show manifest
            print("[3/6] Code viewer")
            await cdp.eval_js(f"({CLICK_NAV})('Code viewer')")
            await cdp.wait_text("See inside")
            print("   inject:", (await cdp.eval_js(f"({INJECT_FILE})('demo.apk')"))["result"]["value"])
            await cdp.wait_text("Manifest", timeout=20)
            await asyncio.sleep(1.0)
            await capture(cdp, "03-code-viewer.png")

            # 4. Evidence report — inject and generate
            print("[4/6] Evidence report")
            await cdp.eval_js(f"({CLICK_NAV})('Evidence report')")
            await cdp.wait_text("Scored findings")
            print("   inject:", (await cdp.eval_js(f"({INJECT_FILE})('demo.apk')"))["result"]["value"])
            await asyncio.sleep(0.5)
            await cdp.eval_js(f"({CLICK_BUTTON})('Generate report')")
            await cdp.wait_text("EVIDENCE REPORT ·", timeout=30)
            await asyncio.sleep(0.6)
            await capture(cdp, "04-evidence-report.png")

            # 5. Projects
            print("[5/6] Projects")
            await cdp.eval_js(f"({CLICK_NAV})('Projects')")
            await cdp.wait_text("PROJECT", timeout=10)
            await capture(cdp, "05-projects.png")

            # 6. Agent tools
            print("[6/6] Agent tools")
            await cdp.eval_js(f"({CLICK_NAV})('Agent tools')")
            await cdp.wait_text("AGENT", timeout=10)
            await capture(cdp, "06-agent-tools.png")

        print("All screenshots written to", OUT)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    asyncio.run(main())
