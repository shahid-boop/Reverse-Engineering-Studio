from fastapi.testclient import TestClient
from revstudio_api.main import app
client = TestClient(app)
def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
def test_create_and_list_project():
    created = client.post("/v1/projects", json={"name":"Test workspace"})
    assert created.status_code == 201
    assert created.json()["name"] == "Test workspace"
    listed = client.get("/v1/projects")
    assert any(p["id"] == created.json()["id"] for p in listed.json())
