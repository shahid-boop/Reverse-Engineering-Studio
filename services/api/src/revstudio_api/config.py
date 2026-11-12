from pydantic_settings import BaseSettings, SettingsConfigDict
class Settings(BaseSettings):
    app_name: str = "Reverse Engineering Studio API"
    version: str = "0.1.0"
    max_upload_mb: int = 100
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    model_config = SettingsConfigDict(env_prefix="REVSTUDIO_", env_file=".env", extra="ignore")
settings = Settings()
