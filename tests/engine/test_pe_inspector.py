from builders import build_minimal_pe64
from revstudio_engine.pe_inspector import inspect_pe


def test_fixture_pe_parses():
    result = inspect_pe("fixture.exe", build_minimal_pe64())
    assert result["format"] == "PE32+"
    assert result["pe"]["machine"] == "AMD64"
    assert result["pe"]["bits"] == 64
    assert result["pe"]["sections"][0]["name"] == ".text"
    assert result["pe"]["entry_point_section"] == ".text"
    assert len(result["sha256"]) == 64


def test_real_windows_executable():
    from pathlib import Path
    exe = Path(r"C:\Windows\System32\where.exe")
    if not exe.exists():
        return
    result = inspect_pe("where.exe", exe.read_bytes())
    pe = result["pe"]
    assert pe["imports"], "expected imports on a real system executable"
    assert pe["sections"], "expected sections"
    assert isinstance(pe["packing_suspected"], bool)


def test_rejects_non_pe():
    try:
        inspect_pe("notpe.bin", b"hello world, definitely not a PE")
    except ValueError:
        return
    assert False, "expected ValueError for non-PE input"
