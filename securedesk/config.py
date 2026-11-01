import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    environment: str = os.getenv("SECUREDESK_ENV", "development").lower()
    api_key: str = os.getenv("SECUREDESK_API_KEY", "")
    web_password: str = os.getenv("SECUREDESK_WEB_PASSWORD", "")
    session_secret: str = os.getenv("SECUREDESK_SESSION_SECRET", "")
    admin_username: str = os.getenv("SECUREDESK_ADMIN_USERNAME", "admin")
    admin_password: str = os.getenv("SECUREDESK_ADMIN_PASSWORD", os.getenv("SECUREDESK_WEB_PASSWORD", ""))
    database: str = os.getenv("SECUREDESK_DATABASE", "./data/securedesk.db")
    cors_origins: tuple[str, ...] = tuple(
        item.strip()
        for item in os.getenv("SECUREDESK_CORS_ORIGINS", "").split(",")
        if item.strip()
    )
    rate_limit: int = max(10, int(os.getenv("SECUREDESK_RATE_LIMIT", "60")))

    @property
    def production(self) -> bool:
        return self.environment == "production"


settings = Settings()
