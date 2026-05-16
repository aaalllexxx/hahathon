import os
from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    APP_NAME: str = "CodeGuardian AI"
    APP_ENV: str = "local"
    APP_HOST: str = "0.0.0.0"
    APP_PORT: int = 8000
    APP_SECRET_KEY: str = "change-me"

    DATABASE_URL: str = "sqlite:///./codeguardian.db"

    GITLAB_URL: str = "http://localhost:8080"
    GITLAB_INTERNAL_URL: str = "http://gitlab"
    GITLAB_PRIVATE_TOKEN: str = "change-me"
    GITLAB_WEBHOOK_SECRET: str = "super-secret-token"
    GITLAB_WEB_PORT: int = 8080
    GITLAB_SSH_PORT: int = 2222
    CODEGUARDIAN_WEBHOOK_URL: str = "http://codeguardian:8000/webhooks/gitlab"

    OPENAI_BASE_URL: str = "http://localhost:1234/v1"
    OPENAI_API_KEY: str = "change-me"
    OPENAI_MODEL: str = "qwen2.5-coder-32b-instruct"
    OPENAI_TIMEOUT: float = 60
    OPENAI_TEMPERATURE: float = 0.1
    OPENAI_MAX_TOKENS: int = 900

    SECURITY_BLOCK_ON_CRITICAL: bool = True
    SECURITY_BLOCK_ON_HIGH: bool = True
    SECURITY_BLOCK_ON_WARNING: bool = False
    SECURITY_USE_LLM: bool = True
    SECURITY_REQUIRE_LLM_REVIEW: bool = True
    SECURITY_FAIL_CLOSED_ON_LLM_ERROR: bool = True
    SECURITY_MAX_DIFF_CHARS: int = 60000

    # Enforcement
    SECURITY_BLOCK_CLOSE_MR: bool = True
    SECURITY_BLOCK_INLINE_COMMENTS: bool = True
    SECURITY_BLOCK_MERGE_REQUESTS: bool = True
    SECURITY_BLOCK_PUSHES: bool = False
    SECURITY_BLOCK_PRE_RECEIVE: bool = False
    SECURITY_PRECHECK_PUBLIC: bool = True
    CODEGUARDIAN_PUBLIC_URL: str = "http://localhost:8000"

    CVE_ENABLE: bool = True
    CVE_OSV_API_URL: str = "https://api.osv.dev"
    CVE_TIMEOUT: float = 10
    CVE_MAX_DEPENDENCIES: int = 20

    DASHBOARD_TITLE: str = "CodeGuardian AI"

    LOG_LEVEL: str = Field(default="INFO")


@lru_cache
def get_settings() -> Settings:
    return Settings(_env_file=os.getenv("CODEGUARDIAN_ENV_FILE", ".env"))


settings = get_settings()
