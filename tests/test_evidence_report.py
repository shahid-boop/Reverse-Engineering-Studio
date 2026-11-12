"""Evidence report generation tests."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

from builders import build_demo_apk, build_minimal_pe64  # noqa: E402

from revstudio_api.main import app  # noqa: E402
from revstudio_engine.apk_inspector import inspect_apk  # noqa: E402
from revstudio_engine.evidence_report import (  # noqa: E402
    build_report,
    render_html,
    render_markdown,
)
from revstudio_engine.pe_inspector import inspect_pe  # noqa: E402

client = TestClient(app)


@pytest.fixture(scope="module")
def pe_report():
    data = build_minimal_pe64()
    return data, build_report("sample.exe", data, inspect_pe("sample.exe", data))


@pytest.fixture(scope="module")
def apk_report():
    data = build_demo_apk()
    return data, build_report("demo.apk", data, inspect_apk("demo.apk", data))


def test_report_structure(pe_report):
    _, report = pe_report
    assert report["schema"] == "revstudio.evidence-report/1"
    assert report["report_id"]
    assert report["generated_at"]
    assert report["subject"]["filename"] == "sample.exe"
    assert len(report["subject"]["sha256"]) == 64
    assert report["subject"]["kind"] == "PE executable"
    assert 0 <= report["risk"]["score"] <= 100
    assert report["risk"]["level"] in {"low", "medium", "high", "critical"}
    assert report["limitations"]


def test_report_findings_are_scored_and_sorted(pe_report):
    _, report = pe_report
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sevs = [order[f["severity"]] for f in report["findings"]]
    assert sevs == sorted(sevs)
    for idx, f in enumerate(report["findings"], start=1):
        assert f["id"] == f"F{idx:02d}"
        assert f["evidence"], "every finding must cite evidence"
        assert f["category"]


def test_unsigned_pe_flags_signing(pe_report):
    _, report = pe_report
    titles = [f["title"] for f in report["findings"]]
    assert any("signature" in t.lower() for t in titles)


def test_apk_report_covers_permissions(apk_report):
    _, report = apk_report
    assert report["subject"]["kind"] == "Android APK"
    assert report["risk"]["counts"].get("info", 0) >= 1  # native libs / signatures
    perm = [f for f in report["findings"] if f["category"] == "permissions"]
    assert perm and perm[0]["evidence"]


def test_report_counts_match_findings(pe_report):
    _, report = pe_report
    total = sum(report["risk"]["counts"].values())
    assert total == len(report["findings"])


def test_markdown_rendering(pe_report):
    _, report = pe_report
    md = render_markdown(report)
    assert md.startswith("# Evidence Report — sample.exe")
    assert "## Findings" in md
    assert "## Limitations" in md
    assert report["markdown"] == md
    assert md.count("### F") == len(report["findings"]) or not report["findings"]


def test_html_rendering_is_self_contained(pe_report):
    _, report = pe_report
    page = render_html(report)
    assert page.startswith("<!doctype html>")
    assert "<style>" in page
    assert "Evidence Report" in page
    assert report["html"] == page
    # no external resources
    assert "http://" not in page.split("<body")[0].replace("http://www.w3", "")
    assert "<script" not in page


def test_report_of_plain_bytes_falls_back():
    from revstudio_engine.static_inspector import inspect_bytes

    data = b"hello world, just text" * 40
    report = build_report("notes.txt", data, inspect_bytes("notes.txt", data))
    assert report["subject"]["kind"]
    assert report["risk"]["score"] >= 0
    assert report["markdown"] and report["html"]


def test_api_report_endpoint():
    data = build_demo_apk()
    response = client.post(
        "/v1/analysis/report",
        files={"file": ("demo.apk", data, "application/vnd.android.package-archive")},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["schema"] == "revstudio.evidence-report/1"
    assert payload["risk"]["level"] in {"low", "medium", "high", "critical"}
    assert isinstance(payload["findings"], list)
    assert payload["markdown"].startswith("# Evidence Report")
    assert "<!doctype html>" in payload["html"]


def test_api_report_flags_excluded():
    data = build_minimal_pe64()
    response = client.post(
        "/v1/analysis/report",
        files={"file": ("a.exe", data, "application/octet-stream")},
        data={"include_markdown": "false", "include_html": "false"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert "markdown" not in payload
    assert "html" not in payload
    assert payload["findings"] is not None
