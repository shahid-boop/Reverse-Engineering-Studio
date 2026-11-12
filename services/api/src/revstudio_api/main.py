from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from revstudio_api.config import settings
from revstudio_api.routes import analysis, deep, projects
app = FastAPI(title=settings.app_name, version=settings.version,
              description="Local-first, evidence-based software inspection API.")
app.add_middleware(CORSMiddleware,
    allow_origins=[x.strip() for x in settings.cors_origins.split(",") if x.strip()],
    allow_credentials=False, allow_methods=["GET","POST"], allow_headers=["*"])
app.include_router(analysis.router, prefix="/v1/analysis", tags=["analysis"])
app.include_router(deep.router, prefix="/v1/analysis", tags=["analysis"])
app.include_router(projects.router, prefix="/v1/projects", tags=["projects"])
@app.get("/health")
def health():
    return {"status":"ok","app":settings.app_name,"version":settings.version}
