from __future__ import annotations

from datetime import timedelta

from django.core.cache import cache
from django.utils import timezone
from django.utils.dateparse import parse_datetime


PRESENCE_STALE_SECONDS = 90
GLOBAL_PRESENCE_CACHE_KEY = 'presence:global:online_user_ids'


def presence_cache_key(conversation_id: int) -> str:
    return f'chat:conversation:{conversation_id}:online_user_ids'


def _get_online_user_ids(cache_key: str) -> set[int]:
    """Return users with a fresh connection in the given presence cache."""
    try:
        connections = cache.get(cache_key) or {}
    except Exception:
        return set()

    if not isinstance(connections, dict):
        return set()

    cutoff = timezone.now() - timedelta(seconds=PRESENCE_STALE_SECONDS)
    online_user_ids = set()

    for cached_user_id, raw_connections in connections.items():
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
                    online_user_ids.add(int(cached_user_id))
                except (TypeError, ValueError):
                    pass
                break

    return online_user_ids


def get_online_user_ids(conversation_id: int) -> set[int]:
    """Return users with a fresh connection for this conversation.

    Cache failures intentionally return an empty set, treating recipients as
    offline so an important message notification is not silently lost.
    """
    return _get_online_user_ids(presence_cache_key(conversation_id))


def get_globally_online_user_ids() -> set[int]:
    """Return users whose authenticated app-wide heartbeat is still fresh."""
    return _get_online_user_ids(GLOBAL_PRESENCE_CACHE_KEY)


def set_global_presence(user_id: int, connection_id: str, online: bool) -> bool:
    """Update one browser connection and return whether the user remains online."""
    try:
        connections = cache.get(GLOBAL_PRESENCE_CACHE_KEY) or {}
    except Exception:
        return False

    if not isinstance(connections, dict):
        connections = {}

    cutoff = timezone.now() - timedelta(seconds=PRESENCE_STALE_SECONDS)
    active_connections = {}

    for cached_user_id, raw_connections in connections.items():
        if not isinstance(raw_connections, dict):
            continue
        fresh_connections = {}
        for cached_connection_id, heartbeat_at_raw in raw_connections.items():
            heartbeat_at = parse_datetime(str(heartbeat_at_raw))
            if not heartbeat_at:
                continue
            if timezone.is_naive(heartbeat_at):
                heartbeat_at = timezone.make_aware(
                    heartbeat_at,
                    timezone.get_default_timezone(),
                )
            if heartbeat_at >= cutoff:
                fresh_connections[str(cached_connection_id)] = heartbeat_at.isoformat()
        if fresh_connections:
            active_connections[str(cached_user_id)] = fresh_connections

    user_key = str(user_id)
    user_connections = dict(active_connections.get(user_key) or {})
    if online:
        user_connections[str(connection_id)] = timezone.now().isoformat()
        active_connections[user_key] = user_connections
    else:
        user_connections.pop(str(connection_id), None)
        if user_connections:
            active_connections[user_key] = user_connections
        else:
            active_connections.pop(user_key, None)

    try:
        if active_connections:
            cache.set(
                GLOBAL_PRESENCE_CACHE_KEY,
                active_connections,
                timeout=PRESENCE_STALE_SECONDS,
            )
        else:
            cache.delete(GLOBAL_PRESENCE_CACHE_KEY)
    except Exception:
        return False

    return user_key in active_connections
