from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    APP_NAME: str = "Overlook"
    APP_VERSION: str = "2.0.0"
    DEBUG: bool = False

    DATABASE_URL: str = "sqlite+aiosqlite:///./sentinel.db"

    NEO4J_ENABLED: bool = False
    NEO4J_URI: str = "bolt://localhost:7687"
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str = "password"

    QDRANT_ENABLED: bool = False
    QDRANT_HOST: str = "localhost"
    QDRANT_PORT: int = 6333

    REDIS_ENABLED: bool = False
    REDIS_URL: str = "redis://localhost:6379"

    JWT_SECRET: str = "your-secret-key-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    OLLAMA_ENABLED: bool = False
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    LLM_MODEL: str = "llama3.1"
    EMBEDDING_MODEL: str = "all-MiniLM-L6-v2"

    CORS_ORIGINS: List[str] = ["http://localhost:3000"]

    MITRE_ATTACK_VERSION: str = "14.1"
    ENABLE_OFFLINE_MODE: bool = False
    HUMAN_APPROVAL_REQUIRED: bool = True

    WORLD_MODEL_SEED_ON_STARTUP: bool = True
    EVIDENCE_HALF_LIFE_HOURS: float = 6.0
    DETECTION_THRESHOLD: float = 0.6
    BELIEF_PROPAGATION_DAMPING: float = 0.45

    LOG_LEVEL: str = "INFO"
    METRICS_ENABLED: bool = True

    class Config:
        env_file = ".env"
        case_sensitive = True
        extra = "ignore"


settings = Settings()
