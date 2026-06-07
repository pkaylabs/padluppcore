from __future__ import annotations

from datetime import timedelta

from django.core.cache import cache
from django.utils import timezone
from django.utils.dateparse import parse_datetime


PRESENCE_STALE_SECONDS = 90


def presence_cache_key(conversation_id: int) -> str:
    return f'chat:conversation:{conversation_id}:online_user_ids'


def get_online_user_ids(conversation_id: int) -> set[int]:
    """Return users with a fresh chat connection for this conversation.

    Cache failures intentionally return an empty set, treating recipients as
    offline so an important message notification is not silently lost.
    """
    try:
        connections = cache.get(presence_cache_key(conversation_id)) or {}
    except Exception:
        return set()

    if not isinstance(connections, dict):
        return set()

    cutoff = timezone.now() - timedelta(seconds=PRESENCE_STALE_SECONDS)
    online_user_ids = set()

    for user_id, raw_connections in connections.items():
        if not isinstance(raw_connections, dict):
            continue
        for heartbeat_at_raw in raw_connections.values():
            heartbeat_at = parse_datetime(str(heartbeat_at_raw))
            if not heartbeat_at:
                continue
            if timezone.is_naive(heartbeat_at):
                heartbeat_at = timezone.make_aware(
                    heartbeat_at,
                    timezone.get_default_timezone(),
                )
            if heartbeat_at >= cutoff:
                try:
                    online_user_ids.add(int(user_id))
                except (TypeError, ValueError):
                    pass
                break

    return online_user_ids
