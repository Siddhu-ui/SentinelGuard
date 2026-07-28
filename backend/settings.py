from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    secret_key: str = "development-only-change-me"
    access_token_expire_minutes: int = 60
    database_url: str = "sqlite:///./sentinelguard.db"
    upload_dir: str = "./uploads"
    cors_origins: str = "http://localhost:5173"
    max_upload_mb: int = 100

    @property
    def upload_path(self) -> Path:
        return Path(self.upload_dir).resolve()

settings = Settings()
