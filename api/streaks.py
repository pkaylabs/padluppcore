from __future__ import annotations

from datetime import date, timedelta

from django.db.models import Q
from django.utils import timezone
from knox.models import AuthToken

from .activity import dt_to_local_date, get_user_tzinfo
from .models import Evidence, Goal, Message, Task, TimerSession, UserDailyActivity


def _longest_consecutive_days(dates: set[date]) -> int:
    ordered = sorted(dates)
    if not ordered:
        return 0

    longest = 1
    current = 1
    previous = ordered[0]
    for activity_date in ordered[1:]:
        if activity_date == previous + timedelta(days=1):
            current += 1
        else:
            current = 1
        longest = max(longest, current)
        previous = activity_date
    return longest


def _current_streak_days(dates: set[date], end_date: date) -> int:
    if end_date not in dates:
        return 0

    count = 1
    cursor = end_date
    while cursor - timedelta(days=1) in dates:
        count += 1
        cursor -= timedelta(days=1)
    return count


def _historical_activity_dates(user, tzinfo) -> set[date]:
    """Reconstruct streak dates for installations not yet backfilled."""
    active_dates: set[date] = set()

    def add_datetime(value) -> None:
        activity_date = dt_to_local_date(value, tzinfo)
        if activity_date:
            active_dates.add(activity_date)

    for created_at in AuthToken.objects.filter(user=user).values_list('created', flat=True).iterator():
        add_datetime(created_at)
    add_datetime(getattr(user, 'last_login', None))

    for started_at, created_at in (
        TimerSession.objects.filter(user=user).values_list('started_at', 'created_at').iterator()
    ):
        add_datetime(started_at or created_at)

    for submitted_at, created_at in (
        Evidence.objects.filter(submitted_by=user).values_list('submitted_at', 'created_at').iterator()
    ):
        add_datetime(submitted_at or created_at)

    for updated_at, created_at in (
        Task.objects.filter(owner=user, status=Task.STATUS_COMPLETED)
        .values_list('updated_at', 'created_at')
        .iterator()
    ):
        add_datetime(updated_at or created_at)

    for created_at, updated_at in (
        Goal.objects.filter(
            Q(user=user) | Q(partnership__user_a=user) | Q(partnership__user_b=user)
        )
        .values_list('created_at', 'updated_at')
        .iterator()
    ):
        add_datetime(created_at)
        add_datetime(updated_at)

    for created_at in Message.objects.filter(sender=user).values_list('created_at', flat=True).iterator():
        add_datetime(created_at)

    return active_dates


def get_streak_stats(user) -> dict[str, int]:
    tzinfo = get_user_tzinfo(user)
    active_dates = set(
        UserDailyActivity.objects.filter(user=user).values_list('activity_date', flat=True)
    )
    if not active_dates:
        active_dates = _historical_activity_dates(user, tzinfo)

    local_today = timezone.localtime(timezone.now(), tzinfo).date()
    return {
        'longest_streak_count': _longest_consecutive_days(active_dates),
        'current_streak_count': _current_streak_days(active_dates, local_today),
    }
