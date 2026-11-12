# Reverse Engineering Studio

Cross-platform starter monorepo for authorized, evidence-based software inspection.

**Targets:** Web, Windows, macOS, Linux, Android.

## Included
- `apps/web`: React + TypeScript dashboard.
- `apps/web/src-tauri`: Tauri 2 desktop shell.
- `apps/mobile`: Capacitor Android wrapper.
- `services/api`: FastAPI local API.
- `services/cli`: command-line static inspector.
- `services/mcp-server`: MCP tools for compatible AI agents.
- `engines/static-analysis`: safe metadata, hashes, basic file signatures, printable strings.
- `packages/shared-types`: shared TypeScript contracts.
- `tests`: API and engine tests.

This is a runnable starter foundation, not a finished REA clone. Deep decompilation, live device control, dynamic sandboxing, and advanced platform analyzers remain future implementation phases.

## Requirements
Node.js 20+, Python 3.11+. Rust stable for desktop builds. Android Studio + Android SDK for Android builds.

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
