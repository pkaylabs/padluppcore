from django.core.management.base import BaseCommand

from accounts.models import User
from api.awards import AWARD_DEFINITIONS, award_progress_for_user, evaluate_user_awards
from api.models import UserAward


class Command(BaseCommand):
    help = 'Grant milestone awards earned from existing Padlupp activity without sending notifications.'

    def add_arguments(self, parser):
        parser.add_argument('--dry-run', action='store_true', help='Report grants without writing them.')
        parser.add_argument('--user-id', type=int, default=None, help='Process only one user id.')

    def handle(self, *args, **options):
        users = User.objects.filter(is_active=True, deleted=False).order_by('id')
        if options['user_id']:
            users = users.filter(id=options['user_id'])

        users_seen = 0
        awards_granted = 0
        for user in users.iterator():
            users_seen += 1
            if options['dry_run']:
                progress = award_progress_for_user(user)
                existing = set(UserAward.objects.filter(user=user).values_list('award_key', flat=True))
                awards_granted += sum(
                    1
                    for definition in AWARD_DEFINITIONS
                    if definition.key not in existing and progress[definition.key] >= definition.target
                )
                continue
            awards_granted += len(evaluate_user_awards(user, notify=False))

        self.stdout.write(
            self.style.SUCCESS(
                f'Completed award backfill. users_seen={users_seen}, '
                f'awards_granted={awards_granted}, dry_run={bool(options["dry_run"])}'
            )
        )
