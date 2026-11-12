from revstudio_engine.static_inspector import detect_format, inspect_bytes
def test_detect_pe_signature():
    assert detect_format(b"MZ" + b"\x00"*10, "sample.exe").startswith("PE")
def test_detect_sqlite():
    assert detect_format(b"SQLite format 3\x00rest") == "SQLite database"
def test_hash_and_strings():
    result = inspect_bytes("hello.bin", b"hello world this is a test")
    assert len(result["sha256"]) == 64
    assert "hello world this is a test" in result["strings_preview"]
def test_empty_file():
    assert inspect_bytes("empty.dat", b"")["size_bytes"] == 0
