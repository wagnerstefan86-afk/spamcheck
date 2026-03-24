from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # API Keys
    openai_api_key: str = ""
    virustotal_api_key: str = ""
    urlscan_api_key: str = ""

    # Service toggles
    enable_virustotal: bool = True
    enable_urlscan: bool = True
    enable_llm: bool = True

    # urlscan config
    urlscan_visibility: str = "private"

    # LLM config
    llm_model: str = "gpt-4o"

    # Polling config
    max_poll_seconds: int = 120
    poll_interval_seconds: int = 5

    # App config
    max_upload_size_mb: int = 25
    database_url: str = "sqlite:///./data/mailscope.db"

    model_config = {"env_file": ".env", "extra": "ignore"}


@lru_cache()
def get_settings() -> Settings:
    return Settings()
