"""Password hashing and JWT issuing/verification."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import bcrypt
from jose import JWTError, jwt

from supplyguard.config import get_settings

#: bcrypt work factor. 12 is roughly 250ms on current hardware — slow enough to
#: make offline cracking expensive, fast enough for an interactive login.
_BCRYPT_ROUNDS = 12


class TokenError(Exception):
    pass


def hash_password(password: str) -> str:
    """Hash a password with bcrypt.

    bcrypt silently truncates input beyond 72 bytes, so a longer passphrase is
    rejected rather than accepted with only its first 72 bytes protecting the
    account — a user who types 100 characters should not be quietly given 72.
    """
    encoded = password.encode("utf-8")
    if len(encoded) > 72:
        raise ValueError("Password must be at most 72 bytes.")
    return bcrypt.hashpw(encoded, bcrypt.gensalt(rounds=_BCRYPT_ROUNDS)).decode("ascii")


def verify_password(password: str, hashed: str) -> bool:
    """Constant-time password check that never raises on malformed input."""
    try:
        return bcrypt.checkpw(password.encode("utf-8")[:72], hashed.encode("ascii"))
    except (ValueError, TypeError, UnicodeEncodeError):
        return False


def create_access_token(subject: str, extra: dict[str, Any] | None = None) -> str:
    settings = get_settings()
    now = datetime.now(UTC)
    payload: dict[str, Any] = {
        "sub": subject,
        "iat": now,
        "exp": now + timedelta(minutes=settings.jwt_expiry_minutes),
        "iss": "supplyguard",
    }
    payload.update(extra or {})
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> dict[str, Any]:
    settings = get_settings()
    try:
        return jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            issuer="supplyguard",
        )
    except JWTError as exc:
        raise TokenError(str(exc)) from exc
