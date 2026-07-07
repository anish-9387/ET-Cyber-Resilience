from pydantic_settings import BaseSettings
from typing import Optional, List
import os

class Settings(BaseSettings):
    APP_NAME: str = "Sentinel-X"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    DATABASE_URL: str = "postgresql+asyncpg://user:pass@localhost:5432/sentinelx"
    NEO4J_URI: str = "bolt://localhost:7687"
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str = "password"
    QDRANT_HOST: str = "localhost"
    QDRANT_PORT: int = 6333
    REDIS_URL: str = "redis://localhost:6379"
    KAFKA_BOOTSTRAP_SERVERS: str = "localhost:9092"

    JWT_SECRET: str = "your-secret-key-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    OLLAMA_BASE_URL: str = "http://localhost:11434"
    LLM_MODEL: str = "llama3.1"
    EMBEDDING_MODEL: str = "all-MiniLM-L6-v2"

    CORS_ORIGINS: List[str] = ["http://localhost:3000"]

    MITRE_ATTACK_VERSION: str = "14.1"
    ENABLE_OFFLINE_MODE: bool = False
    HUMAN_APPROVAL_REQUIRED: bool = True

    LOG_LEVEL: str = "INFO"
    METRICS_ENABLED: bool = True

    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()
