"""
vaultX Configuration - Environment-based settings
"""

from pydantic_settings import BaseSettings
from typing import List, Optional


class Settings(BaseSettings):
    # App
    APP_NAME: str = "vaultX"
    DEBUG: bool = True
    WORKERS: int = 1
    SECRET_KEY: str = "change-me-in-production"

    # Database
    # Local demo uses SQLite so the backend can run without Docker/PostgreSQL.
    DATABASE_URL: str = "sqlite+aiosqlite:///./vaultx_demo.db"
    MONGO_URL: str = "mongodb://localhost:27017/vaultx"

    # Redis / Queue
    # Local demo values. Queue startup should be handled safely in queue_manager.py.
    REDIS_URL: str = "redis://localhost:6379/0"
    RABBITMQ_URL: str = "amqp://guest:guest@localhost:5672/"

    # AI Providers
    # Use ollama as local/demo default to avoid requiring paid API keys at startup.
    AI_PROVIDER: str = "ollama"  # claude | openai | ollama
    ANTHROPIC_API_KEY: Optional[str] = None
    OPENAI_API_KEY: Optional[str] = None
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "llama3:8b"

    # Claude Model
    CLAUDE_MODEL: str = "claude-sonnet-4-20250514"

    # OpenAI Model
    OPENAI_MODEL: str = "gpt-4o"

    # Tool Paths
    # Windows/local demo fallback names. In Linux/Docker, these can be overridden with .env.
    NMAP_PATH: str = "nmap"
    NUCLEI_PATH: str = "nuclei"
    NIKTO_PATH: str = "nikto"
    SQLMAP_PATH: str = "sqlmap"
    AMASS_PATH: str = "amass"
    SUBFINDER_PATH: str = "subfinder"
    WHATWEB_PATH: str = "whatweb"
    ZAP_API_URL: str = "http://localhost:8080"

    # Security
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:80",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8000"
    ]
    MAX_CONCURRENT_SCANS: int = 5
    SCAN_TIMEOUT_SECONDS: int = 3600
    RATE_LIMIT_PER_MINUTE: int = 10

    # Safe Mode
    SAFE_MODE: bool = True
    REQUIRE_SCOPE_CONFIRMATION: bool = True

    # Report Output
    REPORTS_DIR: str = "./reports"
    PDF_TEMPLATE_DIR: str = "./templates"

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()


def get_ai_client():
    """Return the configured AI client based on AI_PROVIDER."""
    provider = settings.AI_PROVIDER.lower()

    if provider == "claude":
        import anthropic
        return anthropic.AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY)

    elif provider == "openai":
        from openai import AsyncOpenAI
        return AsyncOpenAI(api_key=settings.OPENAI_API_KEY)

    elif provider == "ollama":
        import httpx
        return httpx.AsyncClient(base_url=settings.OLLAMA_BASE_URL)

    else:
        raise ValueError(f"Unknown AI provider: {provider}")