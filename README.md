# Reverse Engineering Studio

Cross-platform starter monorepo for authorized, evidence-based software inspection.

**Targets:** Web, Windows, macOS, Linux, Android.

## Included
- `apps/web`: React + TypeScript dashboard (6 pages: Overview, Analysis lab, Code viewer, Evidence report, Projects, Agent tools).
- `apps/web/src-tauri`: Tauri 2 desktop shell.
- `apps/mobile`: Capacitor Android wrapper.
- `services/api`: FastAPI local API.
- `services/cli`: command-line static inspector.
- `services/mcp-server`: MCP tools for compatible AI agents.
- `engines/static-analysis`: safe metadata, hashes, basic file signatures, printable strings.
- `packages/shared-types`: shared TypeScript contracts.
- `tests`: API and engine tests.

## Features

**Deep analysis (PE / APK)**
- PE: headers, sections + entropy, imports/exports, resources, version info, .NET detection, Authenticode, overlay, packing heuristics.
- APK: binary manifest decode (AXML), permissions, components, DEX class outlines, assets, native libs, signatures.

**Code viewer (view / copy / download)**
- Hex dump, printable strings, x86/x64 disassembly (capstone), decoded manifest XML, DEX outline, APK asset source.
- Java sources via **JADX** and resources/smali via **APKTool** (external tools in `tools/`).

**Evidence reports**
- Scored findings (critical/high/medium/low/info) with concrete evidence lines and recommendations.
- Markdown + self-contained HTML export, JSON download.

**Surfaces**
- Web UI, REST API (`/v1/analysis/deep|code-view|report|decompile|tools`), CLI (`revstudio inspect|deep|code|report|decompile|tools`), MCP server (6 tools).

This is a runnable foundation. Live device control, dynamic sandboxing, and advanced platform analyzers remain future implementation phases.

## Requirements
Node.js 20+, Python 3.11+. Rust stable for desktop builds. Android Studio + Android SDK for Android builds.
Optional (for decompilation): a JRE 21+ and the tools described under **External tools**.

## Start API
```bash
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
pip install -e ./engines/static-analysis
pip install -e "services/api[dev]"
uvicorn revstudio_api.main:app --reload --port 8000
```
API docs: http://127.0.0.1:8000/docs

## Start web
```bash
npm install
npm run dev
```
Open http://localhost:5173

## External tools (JADX / APKTool)

Place them under `tools/` (or point `REVSTUDIO_TOOLS` at that directory):

```
tools/
  jre21/          # portable JRE (bin/java.exe)
  jadx/           # jadx zip extracted (bin/jadx.bat, lib/)
  apktool.jar     # APKTool jar
```

Check installation: `GET /v1/analysis/tools`, `revstudio tools`, or the `list_capabilities` MCP tool.

## Tests
```bash
pip install -e ./engines/static-analysis
pip install -e "services/api[dev]"
pytest
```

## CLI and MCP
```bash
pip install -e ./engines/static-analysis
pip install -e ./services/cli
revstudio inspect ./sample.bin
revstudio deep ./sample.apk
revstudio code ./sample.apk --view manifest
revstudio report ./sample.apk
revstudio decompile ./sample.apk --tool jadx --entry MainActivity

pip install -e ./services/mcp-server
revstudio-mcp
```

## Desktop
```bash
npm install
npm run desktop:dev
```
Install the Tauri prerequisites for your operating system first: https://tauri.app/start/prerequisites/

## Android
```bash
npm install
npm run build
npm run mobile:sync
npm run mobile:android
```
Open the Android project in Android Studio; configure signing before release.

## Safety
Files are inspected as data and never executed. Analyze only files you own or are authorized to inspect. Dynamic analysis must later run in a disposable isolated sandbox with explicit consent. Never put API keys in frontend source code.
