import re
import secrets
import time
from collections import defaultdict, deque
from threading import Lock

from fastapi import HTTPException, Request, status

from securedesk.config import settings

_PATTERNS = [
    (re.compile(r"(?i)\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}\\b"), "[EMAIL REDIGIDO]"),
    (re.compile(r"\\b\\d{3}\\.\\d{3}\\.\\d{3}-\\d{2}\\b"), "[CPF REDIGIDO]"),
    (re.compile(r"(?<!\\d)(?:\\+?55\\s?)?(?:\\(?\\d{2}\\)?\\s?)?9?\\d{4}[-. ]?\\d{4}(?!\\d)"), "[TELEFONE REDIGIDO]"),
]


def redact_sensitive_data(value: str) -> str:
    """Mask common identifiers before saving ticket content."""
    for pattern, replacement in _PATTERNS:
        value = pattern.sub(replacement, value)
    return value


def verify_api_key(request: Request) -> None:
    """Accept a signed browser session or a valid bearer token."""
    if request.session.get("authenticated"):
        return
    if not settings.production and not settings.api_key:
        return
    supplied = request.headers.get("Authorization", "")
    token = supplied.removeprefix("Bearer ")
    if (
        not supplied.startswith("Bearer ")
        or not settings.api_key
        or not secrets.compare_digest(token, settings.api_key)
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credencial ausente ou inválida.",
            headers={"WWW-Authenticate": "Bearer"},
        )


class RateLimiter:
    """In-memory request limiter for a single application process."""

    def __init__(self, limit: int, window_seconds: int = 60):
        self.limit = limit
        self.window = window_seconds
        self.events = defaultdict(deque)
        self.lock = Lock()

    def check(self, key: str) -> bool:
        now = time.monotonic()
        with self.lock:
            events = self.events[key]
            while events and now - events[0] >= self.window:
                events.popleft()
            if len(events) >= self.limit:
                return False
            events.append(now)
            return True
