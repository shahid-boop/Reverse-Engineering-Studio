from builders import build_demo_apk, build_minimal_pe64
from revstudio_engine.code_view import available_targets, code_view


def test_hex_dump_view():
    result = code_view("fixture.exe", build_minimal_pe64(), "hex", offset=0, limit=64)
    first = result["content"].splitlines()[0]
    assert first.startswith("00000000")
    assert "4d 5a" in first  # MZ signature bytes
    assert result["truncated"] is True


def test_strings_view():
    payload = b"\x00\x01hello world from strings\x00\x02another long string here\x00"
    result = code_view("data.bin", payload, "strings")
    assert "hello world from strings" in result["content"]
    assert result["line_count"] >= 2


def test_disasm_view_on_pe():
    result = code_view("fixture.exe", build_minimal_pe64(), "disasm", target=".text")
    assert result["meta"]["section"] == ".text"
    assert result["meta"]["bits"] == 64
    assert result["content"]


def test_manifest_view_on_apk():
    result = code_view("demo.apk", build_demo_apk(), "manifest")
    assert result["content"].startswith("<?xml")
    assert result["meta"]["components"]["package"] == "com.revstudio.demo"


def test_dex_view_on_apk():
    result = code_view("demo.apk", build_demo_apk(), "dex")
    assert "class com.revstudio.demo.MainActivity" in result["content"]
    assert "onCreate" in result["content"]


def test_asset_view_on_apk():
    result = code_view("demo.apk", build_demo_apk(), "asset", target="assets/www/app.js")
    assert "api_key" in result["content"]
    assert result["meta"]["asset"] == "assets/www/app.js"


def test_targets_listing():
    targets = available_targets("demo.apk", build_demo_apk())
    kinds = {t["kind"] for t in targets}
    assert {"manifest", "dex", "asset"} <= kinds
    pe_targets = available_targets("fixture.exe", build_minimal_pe64())
    assert any(t["kind"] == "section" for t in pe_targets)


def test_unknown_view_rejected():
    try:
        code_view("x.bin", b"data", "bogus-view")
    except ValueError:
        return
    assert False, "expected ValueError"
