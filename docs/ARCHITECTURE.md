# Architecture

```text
Web UI (React/Vite) ───────┐
Desktop shell (Tauri) ────┼──> FastAPI local service
Android shell (Capacitor) ┘         ├── Project service
                                    ├── Static analysis engine
CLI ────────────────────────────────┤
MCP server ─────────────────────────┘
                                    ├── Future platform analyzers
                                    ├── Future AI/model router
                                    └── Future evidence/report service
```

Principles: local-first, evidence-backed, adapter-based, non-executing by default, and one shared frontend across browser, desktop, and Android.
