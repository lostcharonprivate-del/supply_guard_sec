"""Date parsing helpers tolerant of the many formats registries emit."""

from __future__ import annotations

from datetime import UTC, datetime


def parse_iso(value: object) -> datetime | None:
    """Parse an ISO-8601 timestamp, always returning a timezone-aware UTC value.

    Registries are inconsistent: npm emits `Z`, PyPI emits naive local-looking
    strings, RubyGems emits offsets. Normalising here keeps every downstream
    `now - published` comparison from blowing up on naive/aware mixing.
    """
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                parsed = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
        else:
            return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def utcnow() -> datetime:
    return datetime.now(UTC)


def days_since(value: datetime | None) -> float | None:
    if value is None:
        return None
    return (utcnow() - value).total_seconds() / 86_400.0
