from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from django.core.management.base import BaseCommand
from django.db.models import Q

from accounts.models import User
from knox.models import AuthToken

from api.activity import record_user_activity
from api.models import Evidence, Goal, Message, Task, TimerSession


@dataclass
class BackfillStats:
    users_seen: int = 0
    rows_touched: int = 0


class Command(BaseCommand):
    help = "Backfill UserDailyActivity rows from historical login and activity records."

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Collect counts without writing anything.',
        )
        parser.add_argument(
            '--user-id',
            type=int,
            default=None,
            help='Backfill only one user id.',
        )

    def handle(self, *args, **options):
        dry_run = bool(options['dry_run'])
        user_id = options['user_id']

        users = User.objects.all().order_by('id')
        if user_id:
            users = users.filter(id=user_id)

        stats = BackfillStats()
        self.stdout.write(self.style.NOTICE('[BACKFILL] Starting daily activity backfill...'))
        if dry_run:
            self.stdout.write(self.style.WARNING('[BACKFILL] Dry run enabled; no writes will be performed.'))

        for user in users.iterator():
            stats.users_seen += 1
            user_days_before = stats.rows_touched

            timestamps_by_day = defaultdict(list)

            def add_ts(ts):
                if ts:
                    timestamps_by_day[ts.date()].append(ts)

            for ts in User.objects.filter(id=user.id, last_login__isnull=False).values_list('last_login', flat=True):
                add_ts(ts)
            for ts in AuthToken.objects.filter(user=user).values_list('created', flat=True):
                add_ts(ts)
            for started_at, created_at in TimerSession.objects.filter(user=user).values_list('started_at', 'created_at'):
                add_ts(started_at or created_at)
            for submitted_at, created_at in Evidence.objects.filter(submitted_by=user).values_list('submitted_at', 'created_at'):
                add_ts(submitted_at or created_at)
            for ts in Message.objects.filter(sender=user).values_list('created_at', flat=True):
                add_ts(ts)
            for updated_at, created_at in Task.objects.filter(owner=user, status=Task.STATUS_COMPLETED).values_list('updated_at', 'created_at'):
                add_ts(updated_at or created_at)
            for created_at, updated_at in Goal.objects.filter(
                Q(user=user) |
                Q(partnership__user_a=user) |
                Q(partnership__user_b=user)
            ).values_list('created_at', 'updated_at'):
                add_ts(created_at)
                add_ts(updated_at)

            for _, timestamps in sorted(timestamps_by_day.items()):
                ts = max(timestamps)
                if not dry_run:
                    record_user_activity(user, at=ts, source='backfill')
                stats.rows_touched += 1

            user_days_processed = stats.rows_touched - user_days_before

            if user_days_processed == 0:
                self.stdout.write(f'[BACKFILL] User {user.id}: no source rows found.')
            else:
                self.stdout.write(f'[BACKFILL] User {user.id}: processed {user_days_processed} local days.')

        self.stdout.write(
            self.style.SUCCESS(
                f"[BACKFILL] Completed. users_seen={stats.users_seen}, local_days_processed={stats.rows_touched}, dry_run={dry_run}"
            )
        )
