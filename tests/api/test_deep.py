import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from builders import build_demo_apk, build_minimal_pe64
from fastapi.testclient import TestClient
from revstudio_api.main import app

client = TestClient(app)


def test_deep_pe_endpoint():
    response = client.post(
        "/v1/analysis/deep",
        files={"file": ("fixture.exe", build_minimal_pe64(), "application/octet-stream")},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["format"] == "PE32+"
    assert payload["pe"]["machine"] == "AMD64"
    assert payload["pe"]["sections"]


def test_deep_apk_endpoint():
    response = client.post(
        "/v1/analysis/deep",
        files={"file": ("demo.apk", build_demo_apk(), "application/vnd.android.package-archive")},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["apk"]["package"] == "com.revstudio.demo"
    assert payload["apk"]["manifest_xml"]
    assert payload["apk"]["permissions"]


def test_deep_unknown_format_falls_back():
    response = client.post(
        "/v1/analysis/deep",
        files={"file": ("notes.txt", b"just some plain text notes", "text/plain")},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["deep_supported"] is False
    assert payload["sha256"]


def test_code_view_hex_endpoint():
    response = client.post(
        "/v1/analysis/code-view",
        data={"view": "hex", "offset": "0", "limit": "32"},
        files={"file": ("fixture.exe", build_minimal_pe64(), "application/octet-stream")},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["view"] == "hex"
    assert "4d 5a" in payload["content"]


def test_code_view_targets_endpoint():
    response = client.post(
        "/v1/analysis/code-view",
        data={"view": "targets"},
        files={"file": ("demo.apk", build_demo_apk(), "application/octet-stream")},
    )
    assert response.status_code == 200
    targets = response.json()["meta"]["targets"]
    assert any(t["kind"] == "manifest" for t in targets)


def test_code_view_manifest_endpoint():
    response = client.post(
        "/v1/analysis/code-view",
        data={"view": "manifest"},
        files={"file": ("demo.apk", build_demo_apk(), "application/octet-stream")},
    )
    assert response.status_code == 200
    assert response.json()["content"].startswith("<?xml")


def test_code_view_bad_view_rejected():
    response = client.post(
        "/v1/analysis/code-view",
        data={"view": "nope"},
        files={"file": ("x.bin", b"data", "application/octet-stream")},
    )
    assert response.status_code == 400
