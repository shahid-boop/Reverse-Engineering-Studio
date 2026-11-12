from revstudio_engine.web_inspector import analyze_web_source

def test_javascript_analysis():
    code = b"""
import React from 'react';
export function greet(name) { return name; }
class App {}
const result = fetch('/api/users');
"""
    result = analyze_web_source("app.js", code)
    assert result["language"] == "JavaScript"
    assert result["imports"]
    assert result["functions"]
    assert result["classes"]
    assert result["api_endpoints"]
    assert len(result["sha256"]) == 64

def test_secret_is_redacted():
    result = analyze_web_source(
        "config.ts",
        b'const api_key = "abcdef123456789";'
    )
    assert result["secret_findings"]
    assert "abcdef123456789" not in str(result["secret_findings"])

def test_dynamic_code_pattern():
    result = analyze_web_source("app.js", b"eval(userInput);")
    assert any(x["type"] == "dynamic_eval" for x in result["suspicious_patterns"])

def test_unsupported_extension():
    try:
        analyze_web_source("program.exe", b"hello")
    except ValueError:
        return
    assert False, "Unsupported extension should be rejected"
