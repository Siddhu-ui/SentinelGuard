from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    secret_key: str = "development-only-change-me"
    access_token_expire_minutes: int = 60
    database_url: str = "sqlite:///./sentinelguard.db"
    upload_dir: str = "./uploads"
    protected_dir: str = "./protected"
    # Vite may be opened through either hostname during local development.
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    max_upload_mb: int = 100

    @property
    def upload_path(self) -> Path:
        return Path(self.upload_dir).resolve()

    @property
    def protected_path(self) -> Path:
        return Path(self.protected_dir).resolve()

settings = Settings()
