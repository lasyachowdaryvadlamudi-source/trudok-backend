import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    APP_NAME: str = "TruDok AI Document & Identity Screening API"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    API_KEY: str = os.getenv("API_KEY", "trudok-sih26188-secret-key-2026")
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./trudok.db")
    MAX_FILE_SIZE_MB: int = 5
    ALLOWED_EXTENSIONS: set = {"image/jpeg", "image/jpg", "image/png"}
    RATE_LIMIT_PER_MINUTE: str = "10/minute"
    
    # Explicit CORS allow-list (No wildcard '*' in production)
    ALLOWED_ORIGINS: str = os.getenv(
        "ALLOWED_ORIGINS",
        "https://verilens-nu.vercel.app,https://verilens.vercel.app,http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173"
    )

    @property
    def cors_origins_list(self) -> list:
        origins = [orig.strip() for orig in self.ALLOWED_ORIGINS.split(",") if orig.strip()]
        if self.ENVIRONMENT == "development":
            origins.extend(["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000"])
        return list(set(origins))

    class Config:
        env_file = ".env"
        extra = "allow"

settings = Settings()
