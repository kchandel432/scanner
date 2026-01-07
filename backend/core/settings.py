"""
Application settings using Pydantic v2
"""

from typing import List, Optional
from pathlib import Path
from pydantic_settings import BaseSettings
from pydantic import Field, field_validator, ConfigDict
import os


class Settings(BaseSettings):
    """Application settings"""

    # ======================
    # Application
    # ======================
    APP_NAME: str = "Cyber Risk Intelligence"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = Field(default=True)
    HOST: str = Field(default="0.0.0.0")
    PORT: int = Field(default=8000)

    # ======================
    # Security
    # ======================
    SECRET_KEY: str = Field(
        default="your-secret-key-change-in-production"
    )
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # ======================
    # CORS
    # ======================
    ALLOWED_ORIGINS: List[str] = Field(
        default_factory=lambda: [
            "http://localhost:8000",
            "http://127.0.0.1:8000",
        ]
    )

    # ======================
    # Database
    # ======================
    DATABASE_URL: str = Field(
        default="postgresql://user:password@localhost/cyber_risk"
    )

    # ======================
    # Redis
    # ======================
    REDIS_URL: str = Field(
        default="redis://localhost:6379/0"
    )

    # ======================
    # Storage
    # ======================
    UPLOAD_DIR: Path = Field(default=Path("./uploads"))
    MAX_UPLOAD_SIZE: int = 100 * 1024 * 1024  # 100MB

    # ======================
    # External APIs
    # ======================
    VIRUSTOTAL_API_KEY: Optional[str] = None
    SHODAN_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None

    # ======================
    # ML Models
    # ======================
    ML_MODELS_DIR: Path = Field(default=Path("./ml/models"))

    # ======================
    # Email
    # ======================
    SMTP_SERVER: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USER: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None

    # ======================
    # Rate limiting
    # ======================
    RATE_LIMIT_PER_MINUTE: int = 60

    # ======================
    # Pydantic v2 config
    # ======================
    model_config = ConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
    )

    # ======================
    # Validators
    # ======================
    @field_validator("UPLOAD_DIR", "ML_MODELS_DIR")
    @classmethod
    def create_directories(cls, v: Path):
        v.mkdir(parents=True, exist_ok=True)
        return v


# Global settings instance
settings = Settings()
