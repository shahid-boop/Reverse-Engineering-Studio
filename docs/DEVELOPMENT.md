# Development

Install local packages:
```bash
pip install -e ./engines/static-analysis
pip install -e "services/api[dev]"
pip install -e ./services/cli
pip install -e ./services/mcp-server
```

Run tests:
```bash
pytest tests
```

Build web: `npm run build`

Desktop: `npm run desktop:build` (requires Tauri OS prerequisites).

Android: `npm run build && npm run mobile:sync && npm run mobile:android`.

The project shell and wrappers are configured, but platform installers/signing and production deployment have not yet been performed.
