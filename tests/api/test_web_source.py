from fastapi.testclient import TestClient
from revstudio_api.main import app

client = TestClient(app)

def test_web_source_endpoint():
    response = client.post(
        "/v1/analysis/web-source",
        files={"file": ("app.js", b"function hello() { return fetch('/api/test'); }",
                        "text/javascript")},
    )
    assert response.status_code == 200
    result = response.json()
    assert result["language"] == "JavaScript"
    assert result["api_endpoints"]

def test_web_source_rejects_unsupported_file():
    response = client.post(
        "/v1/analysis/web-source",
        files={"file": ("program.exe", b"MZ", "application/octet-stream")},
    )
    assert response.status_code == 400
