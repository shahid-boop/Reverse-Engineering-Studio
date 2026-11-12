from __future__ import annotations

import hashlib
import re
from pathlib import Path

SUPPORTED_EXTENSIONS = {
    ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx",
    ".html", ".css", ".vue", ".svelte", ".json", ".map",
}

def _matches(pattern: str, source: str, group: int = 0) -> list[dict]:
    results = []
    seen = set()
    for match in re.finditer(pattern, source, re.MULTILINE):
        value = match.group(group).strip()
        line = source.count("\n", 0, match.start()) + 1
        key = (line, value)
        if value and key not in seen:
            results.append({"name": value[:200], "line": line})
            seen.add(key)
    return results

def analyze_web_source(filename: str, data: bytes) -> dict:
    if not filename or not isinstance(data, bytes):
        raise ValueError("A filename and byte content are required.")

    extension = Path(filename).suffix.lower()
    if extension not in SUPPORTED_EXTENSIONS:
        raise ValueError(f"Unsupported web source extension: {extension or '(none)'}")

    if not data:
        raise ValueError("The uploaded source file is empty.")

    source = data.decode("utf-8-sig", errors="replace")
    warnings = [
        "Static analysis only: source code was not executed.",
        "Pattern-based results may contain false positives or miss obfuscated code.",
    ]
    if "\ufffd" in source:
        warnings.append("Some bytes were not valid UTF-8 and were replaced during decoding.")

    imports = _matches(
        r"""(?:\bimport\s+(?:[^;\n]*?\s+from\s+)?|\
\bexport\s+[^;\n]*?\s+from\s+|\
\b(?:const|let|var)\s+[^;\n]*?=\s*require\s*\()\s*['"]([^'"]+)['"]""",
        source, 1,
    )
    functions = _matches(
        r"\bfunction\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(",
        source, 1,
    ) + _matches(
        r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>",
        source, 1,
    )
    functions.sort(key=lambda item: item["line"])

    classes = _matches(r"\bclass\s+([A-Za-z_$][\w$]*)", source, 1)
    exports = _matches(
        r"\bexport\s+(?:default\s+)?(?:async\s+)?"
        r"(?:function|class|const|let|var)?\s*([A-Za-z_$][\w$]*)?",
        source,
    )
    urls = _matches(r"""https?://[^\s"'`<>]+""", source)
    endpoints = _matches(
        r"""(?:fetch|axios\.(?:get|post|put|patch|delete)|\
\.get|\.post|\.put|\.patch|\.delete)\s*\(\s*['"`]([^'"`]+)""",
        source, 1,
    )

    secrets = []
    secret_pattern = re.compile(
        r"""(?i)\b(api[_-]?key|secret|token|password|passwd|client_secret)\b"""
        r"""\s*[:=]\s*(['"])([^'"]{6,})\2"""
    )
    for match in secret_pattern.finditer(source):
        value = match.group(3)
        secrets.append({
            "type": match.group(1).lower(),
            "line": source.count("\n", 0, match.start()) + 1,
            "value_redacted": value[:2] + "..." + value[-2:],
        })

    suspicious_patterns = []
    for label, pattern in [
        ("dynamic_eval", r"\beval\s*\("),
        ("dynamic_function", r"\bnew\s+Function\s*\("),
        ("document_write", r"\bdocument\.write\s*\("),
        ("html_injection", r"\.innerHTML\s*="),
    ]:
        for item in _matches(pattern, source):
            suspicious_patterns.append({"type": label, "line": item["line"]})

    return {
        "filename": Path(filename).name,
        "language": {
            ".ts": "TypeScript", ".tsx": "TypeScript JSX",
            ".js": "JavaScript", ".jsx": "JavaScript JSX",
            ".mjs": "JavaScript module", ".cjs": "CommonJS",
            ".html": "HTML", ".css": "CSS",
            ".vue": "Vue", ".svelte": "Svelte",
            ".json": "JSON", ".map": "Source map",
        }[extension],
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "line_count": len(source.splitlines()),
        "analysis_mode": "static_pattern_analysis",
        "imports": imports,
        "functions": functions,
        "classes": classes,
        "exports": exports,
        "urls": urls,
        "api_endpoints": endpoints,
        "secret_findings": secrets,
        "suspicious_patterns": suspicious_patterns,
        "warnings": warnings,
    }
