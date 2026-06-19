"""Simple in-memory session management for authenticated teacher actions."""

from datetime import datetime, timedelta, timezone
from typing import Dict, Optional
import os
import secrets


SESSION_TTL_MINUTES = int(os.getenv("MHS_SESSION_TTL_MINUTES", "120"))
_sessions: Dict[str, Dict[str, datetime | str]] = {}


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _cleanup_expired_sessions() -> None:
    now = _now_utc()
    expired_tokens = [
        token
        for token, session in _sessions.items()
        if session["expires_at"] <= now
    ]
    for token in expired_tokens:
        _sessions.pop(token, None)


def create_session(username: str) -> str:
    """Create a new session token for a username and return the token."""
    _cleanup_expired_sessions()
    token = secrets.token_urlsafe(32)
    _sessions[token] = {
        "username": username,
        "expires_at": _now_utc() + timedelta(minutes=SESSION_TTL_MINUTES),
    }
    return token


def validate_session(token: str) -> Optional[str]:
    """Return username for a valid token, otherwise return None."""
    _cleanup_expired_sessions()
    session = _sessions.get(token)
    if not session:
        return None
    return str(session["username"])


def revoke_session(token: str) -> None:
    """Invalidate a session token if it exists."""
    _sessions.pop(token, None)
