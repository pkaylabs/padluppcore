from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo

from django.db import IntegrityError
from django.utils import timezone

from .models import Profile, UserDailyActivity


def get_user_tzinfo(user):
    profile = Profile.objects.filter(user=user).only('time_zone').first()
    tz_name = (getattr(profile, 'time_zone', None) or '').strip() if profile else ''
    if tz_name:
        try:
            return ZoneInfo(tz_name)
        except Exception:
            pass
    return timezone.get_default_timezone()


def dt_to_local_date(dt: datetime | None, tzinfo):
    if not dt:
        return None
    if timezone.is_naive(dt):
        dt = timezone.make_aware(dt, timezone.get_default_timezone())
    return timezone.localtime(dt, tzinfo).date()


def record_user_activity(user, *, at: datetime | None = None, source: str = '') -> None:
    """Upsert one daily activity row per user/local-day.

    This keeps streak reads fast and resilient as activity volume grows.
    """
    if not user or not getattr(user, 'pk', None):
        return

    ts = at or timezone.now()
    tzinfo = get_user_tzinfo(user)
    local_date = dt_to_local_date(ts, tzinfo)
    if not local_date:
        return

    try:
        row, created = UserDailyActivity.objects.get_or_create(
            user=user,
            activity_date=local_date,
            defaults={
                'first_activity_at': ts,
                'last_activity_at': ts,
                'source': source or '',
            },
        )
    except IntegrityError:
        row = UserDailyActivity.objects.filter(user=user, activity_date=local_date).first()
        created = False
        if not row:
            return

    if created:
        return

    update_fields = []

    if ts and (not row.first_activity_at or ts < row.first_activity_at):
        row.first_activity_at = ts
        update_fields.append('first_activity_at')

    if ts and (not row.last_activity_at or ts > row.last_activity_at):
        row.last_activity_at = ts
        update_fields.append('last_activity_at')
        if source and source != row.source:
            row.source = source
            update_fields.append('source')
    elif source and not row.source:
        row.source = source
        update_fields.append('source')

    if update_fields:
        row.save(update_fields=update_fields)
