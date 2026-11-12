from builders import build_demo_apk, build_demo_manifest_axml, build_dex
from revstudio_engine.axml import parse_axml
from revstudio_engine.dex import parse_dex
from revstudio_engine.apk_inspector import inspect_apk


def test_axml_manifest_decodes():
    result = parse_axml(build_demo_manifest_axml())
    components = result["components"]
    assert components["package"] == "com.revstudio.demo"
    assert components["version_name"] == "2.1.0"
    assert components["min_sdk"] == "24"
    assert "android.permission.INTERNET" in components["permissions"]
    assert components["launchable_activity"] == "com.revstudio.demo.MainActivity"
    assert 'package="com.revstudio.demo"' in result["xml"]
    assert "xmlns:android=" in result["xml"]


def test_axml_rejects_garbage():
    from revstudio_engine.axml import AxmlError
    try:
        parse_axml(b"\x00\x01\x02\x03garbagegarbage")
    except AxmlError:
        return
    assert False, "expected AxmlError"


def test_dex_structure():
    result = parse_dex(build_dex(), "classes.dex")
    assert result["counts"]["classes"] == 2
    names = [cls["name"] for cls in result["classes"]]
    assert "com.revstudio.demo.MainActivity" in names
    main = next(cls for cls in result["classes"] if cls["name"].endswith("MainActivity"))
    method_names = [m["name"] for m in main["methods"]]
    assert "onCreate" in method_names
    assert any(m["kind"] == "direct" for m in main["methods"])
    assert result["dex_version"] == "035"


def test_dex_rejects_non_dex():
    from revstudio_engine.dex import DexError
    try:
        parse_dex(b"not a dex file at all, really")
    except DexError:
        return
    assert False, "expected DexError"


def test_apk_deep_analysis():
    result = inspect_apk("demo.apk", build_demo_apk())
    apk = result["apk"]
    assert apk["package"] == "com.revstudio.demo"
    assert apk["version_code"] == "21"
    assert len(apk["permissions"]) == 3
    assert apk["activities"] == ["com.revstudio.demo.MainActivity"]
    assert apk["services"] == ["com.revstudio.demo.SyncService"]
    assert apk["receivers"] == ["com.revstudio.demo.BootReceiver"]
    assert apk["providers"] == ["com.revstudio.demo.DataProvider"]
    assert apk["manifest_xml"] and "<manifest" in apk["manifest_xml"]
    assert apk["dex"][0]["counts"]["classes"] == 2
    assert len(apk["assets"]) == 3
    assert len(apk["native_libs"]) == 2
    assert apk["entries_count"] >= 10
    assert apk["signatures"]
    assert apk["has_resources_table"] is True


def test_apk_rejects_non_zip():
    try:
        inspect_apk("fake.apk", b"PK not really a zip")
    except ValueError:
        return
    assert False, "expected ValueError"
