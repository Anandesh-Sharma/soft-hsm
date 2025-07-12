from typing import List, Optional
from pydantic_settings import BaseSettings
from pydantic import Field, validator
import os


class Settings(BaseSettings):
    # API Configuration
    API_V1_PREFIX: str = "/api/v1"
    PROJECT_NAME: str = "HSM Edwards API"
    VERSION: str = "1.0.0"
    DEBUG: bool = Field(default=False, env="DEBUG")
    
    # Database Configuration
    DATABASE_URL: str = Field(..., env="DATABASE_URL")
    DATABASE_POOL_SIZE: int = Field(default=20, env="DATABASE_POOL_SIZE")
    DATABASE_MAX_OVERFLOW: int = Field(default=40, env="DATABASE_MAX_OVERFLOW")
    DATABASE_POOL_TIMEOUT: int = Field(default=30, env="DATABASE_POOL_TIMEOUT")
    
    # HSM Configuration
    HSM_LIBRARY_PATH: str = Field(..., env="HSM_LIBRARY_PATH")
    HSM_SLOT_ID: int = Field(..., env="HSM_SLOT_ID")
    HSM_PIN: str = Field(..., env="HSM_PIN")
    HSM_TOKEN_LABEL: str = Field(default="HSM_TOKEN", env="HSM_TOKEN_LABEL")
    
    # Authentication disabled - no JWT configuration needed
    
    # CORS Configuration
    CORS_ORIGINS: List[str] = Field(default=["http://localhost:8000"], env="CORS_ORIGINS")
    CORS_ALLOW_CREDENTIALS: bool = Field(default=True, env="CORS_ALLOW_CREDENTIALS")
    CORS_ALLOW_METHODS: List[str] = Field(default=["*"], env="CORS_ALLOW_METHODS")
    CORS_ALLOW_HEADERS: List[str] = Field(default=["*"], env="CORS_ALLOW_HEADERS")
    
    # Security Configuration
    MAX_REQUEST_SIZE: int = Field(default=1048576, env="MAX_REQUEST_SIZE")  # 1MB
    BCRYPT_ROUNDS: int = Field(default=12, env="BCRYPT_ROUNDS")
    API_KEY_LENGTH: int = Field(default=32, env="API_KEY_LENGTH")
    
    # Rate Limiting Configuration
    RATE_LIMIT_REQUESTS: int = Field(default=100, env="RATE_LIMIT_REQUESTS")
    RATE_LIMIT_WINDOW: int = Field(default=60, env="RATE_LIMIT_WINDOW")  # seconds
    
    # Redis Configuration (for caching and rate limiting)
    REDIS_URL: Optional[str] = Field(default=None, env="REDIS_URL")
    
    # Logging Configuration
    LOG_LEVEL: str = Field(default="INFO", env="LOG_LEVEL")
    LOG_FORMAT: str = Field(default="json", env="LOG_FORMAT")
    LOG_FILE_PATH: Optional[str] = Field(default=None, env="LOG_FILE_PATH")
    
    # Performance Configuration
    WORKER_COUNT: int = Field(default=4, env="WORKER_COUNT")
    WORKER_TIMEOUT: int = Field(default=120, env="WORKER_TIMEOUT")
    
    # Application Security
    SECRET_KEY: str = Field(..., env="SECRET_KEY")
    ALLOWED_HOSTS: List[str] = Field(default=["*"], env="ALLOWED_HOSTS")
    TRUST_PROXY_HEADERS: bool = Field(default=False, env="TRUST_PROXY_HEADERS")
    
    @validator("CORS_ORIGINS", pre=True)
    def parse_cors_origins(cls, v):
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v
    
    @validator("LOG_LEVEL")
    def validate_log_level(cls, v):
        allowed_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in allowed_levels:
            raise ValueError(f"Log level must be one of: {allowed_levels}")
        return v.upper()
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


# Global settings instance
settings = Settings()