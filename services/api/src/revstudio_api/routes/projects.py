from datetime import datetime, timezone
from uuid import uuid4
from fastapi import APIRouter
from pydantic import BaseModel, Field
router = APIRouter()
# In-memory starter only; replace with SQLite/PostgreSQL persistence in a later phase.
_projects: list[dict] = []
class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
@router.get("")
def list_projects(): return _projects
@router.post("", status_code=201)
def create_project(payload: ProjectCreate):
    project = {"id":str(uuid4()),"name":payload.name.strip(),
               "created_at":datetime.now(timezone.utc).isoformat()}
    _projects.append(project)
    return project
