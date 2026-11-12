from fastapi import APIRouter, File, HTTPException, UploadFile
from revstudio_api.config import settings
from revstudio_engine.static_inspector import inspect_bytes
router = APIRouter()
@router.post("/static-file")
async def inspect_static_file(file: UploadFile = File(...)):
    if not file.filename: raise HTTPException(status_code=400, detail="A filename is required.")
    content = await file.read()
    if len(content) > settings.max_upload_mb * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File exceeds configured upload limit.")
    try: return inspect_bytes(file.filename, content)
    except ValueError as exc: raise HTTPException(status_code=400, detail=str(exc)) from exc
