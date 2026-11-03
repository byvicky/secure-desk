import hashlib
import hmac
import re
import secrets
import sqlite3
import time
from collections import defaultdict, deque
from pathlib import Path
from threading import Lock

from fastapi import Depends, HTTPException, Request, status

from securedesk.config import settings

_PASSWORD_ITERATIONS = 310_000
_PATTERNS = [
    (re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"), "[EMAIL REDIGIDO]"),
    (re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b"), "[CPF REDIGIDO]"),
    (re.compile(r"(?i)\bCPF\s*[:#-]?\s*\d{11}\b"), "[CPF REDIGIDO]"),
    (re.compile(r"(?<!\d)(?:\+?55\s?)?(?:\(?\d{2}\)?\s?)?9?\d{4}[-. ]?\d{4}(?!\d)"), "[TELEFONE REDIGIDO]"),
]


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PASSWORD_ITERATIONS)
    return "pbkdf2_sha256" + "$" + str(_PASSWORD_ITERATIONS) + "$" + salt.hex() + "$" + digest.hex()


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt_hex, digest_hex = encoded.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        iteration_count = int(iterations)
        salt = bytes.fromhex(salt_hex)
        expected_digest = bytes.fromhex(digest_hex)
        # Bound attacker-controlled hash parameters before performing expensive work.
        if not 100_000 <= iteration_count <= 1_000_000:
            return False
        if len(salt) != 16 or len(expected_digest) != 32:
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt, iteration_count
        )
        return hmac.compare_digest(digest, expected_digest)
    except (ValueError, TypeError):
        return False


def rate_limit_bucket(*parts: str) -> str:
    """Return a keyed pseudonymous bucket so raw IPs/usernames are not stored in SQLite."""
    secret = (
        getattr(settings, "session_secret", "")
        or getattr(settings, "api_key", "")
        or "development-only-rate-limit-key"
    )
    message = "\\0".join(parts).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def redact_sensitive_data(value: str) -> str:
    """Mask common identifiers before saving ticket content."""
    for pattern, replacement in _PATTERNS:
        value = pattern.sub(replacement, value)
    return value


def get_current_user(request: Request) -> dict:
    user = request.session.get("user")
    if user and isinstance(user, dict) and user.get("id") and user.get("role") in {"admin", "agent"}:
        from securedesk.database import get_user_by_id

        current = get_user_by_id(user["id"])
        if current and current["active"] and current["role"] == user["role"]:
            return {"id": current["id"], "username": current["username"], "role": current["role"]}
        request.session.clear()
    if not settings.production and not settings.web_password and not getattr(settings, "admin_password", ""):
        return {"id": 0, "username": "local-dev", "role": "admin"}
    supplied = request.headers.get("Authorization", "")
    token = supplied.removeprefix("Bearer ")
    if supplied.startswith("Bearer ") and settings.api_key and secrets.compare_digest(token, settings.api_key):
        return {"id": 0, "username": "api-token", "role": "admin"}
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Autenticação necessária.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_admin(user: dict = Depends(get_current_user)) -> dict:  # noqa: B008
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Permissão de administrador necessária.")
    return user


def verify_csrf(request: Request) -> None:
    """Require a session-bound token for cookie-authenticated state changes."""
    authorization = request.headers.get("Authorization", "")
    if authorization.startswith("Bearer ") or (
        not settings.production and not settings.web_password
        and not getattr(settings, "admin_password", "")
    ):
        return
    user = request.session.get("user")
    if not user:
        return
    expected = request.session.get("csrf_token", "")
    supplied = request.headers.get("X-CSRF-Token", "")
    if not expected or not supplied or not secrets.compare_digest(expected, supplied):
        raise HTTPException(status_code=403, detail="Token CSRF inválido ou ausente.")


def verify_api_key(request: Request) -> None:
    get_current_user(request)


class RateLimiter:
    """Atomic sliding-window limiter; SQLite storage can be shared by worker processes."""

    def __init__(self, limit: int, window_seconds: int = 60, storage_path: str | None = None):
        self.limit = limit
        self.window = window_seconds
        self.storage_path = storage_path
        self.events = defaultdict(deque)
        self.lock = Lock()
        if self.storage_path:
            path = Path(self.storage_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(path, timeout=10) as db:
                db.execute(
                    "CREATE TABLE IF NOT EXISTS rate_limit_events "
                    "(bucket TEXT NOT NULL, occurred_at REAL NOT NULL)"
                )
                db.execute(
                    "CREATE INDEX IF NOT EXISTS idx_rate_limit_bucket_time "
                    "ON rate_limit_events(bucket, occurred_at)"
                )
                db.execute(
                    "CREATE INDEX IF NOT EXISTS idx_rate_limit_occurred_at "
                    "ON rate_limit_events(occurred_at)"
                )

    def reset(self, key: str) -> None:
        if self.storage_path:
            with sqlite3.connect(self.storage_path, timeout=10) as db:
                db.execute("DELETE FROM rate_limit_events WHERE bucket=?", (key,))
            return
        with self.lock:
            self.events.pop(key, None)

    def check(self, key: str) -> bool:
        if self.storage_path:
            now = time.time()
            cutoff = now - self.window
            with sqlite3.connect(self.storage_path, timeout=10, isolation_level=None) as db:
                db.execute("BEGIN IMMEDIATE")
                # Opportunistically prune expired events across all buckets, not only
                # the client currently making a request. The timestamp index keeps this
                # cleanup bounded as the table grows.
                db.execute(
                    "DELETE FROM rate_limit_events WHERE occurred_at<=?", (cutoff,)
                )
                count = db.execute(
                    "SELECT COUNT(*) FROM rate_limit_events WHERE bucket=?", (key,)
                ).fetchone()[0]
                if count >= self.limit:
                    db.execute("COMMIT")
                    return False
                db.execute(
                    "INSERT INTO rate_limit_events(bucket,occurred_at) VALUES(?,?)",
                    (key, now),
                )
                db.execute("COMMIT")
                return True

        now = time.monotonic()
        with self.lock:
            events = self.events[key]
            while events and now - events[0] >= self.window:
                events.popleft()
            if len(events) >= self.limit:
                return False
            events.append(now)
            return True
