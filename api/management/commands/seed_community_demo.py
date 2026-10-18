"""Local acceptance fixtures; refuses to run against an ordinary database."""
import json
from datetime import timedelta

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.files import File
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from api.community_models import CommunityCategory, CommunityGroup, CommunityTask
from api.community_services import _activate_group, create_group, create_task, invite_task_users, join_task, decide_task_request
from api.models import Message, Profile


class Command(BaseCommand):
    help = 'Seed isolated community-verification SQLite fixtures for local browser acceptance testing.'

    def add_arguments(self, parser):
        parser.add_argument('--password', required=True)
        parser.add_argument('--avatar-file')

    @transaction.atomic
    def handle(self, *args, **options):
        database = str(settings.DATABASES['default']['NAME'])
        if not settings.DEBUG or 'community-verification' not in database:
            raise CommandError('Use DEBUG with a separate community-verification database. No data was changed.')
        if CommunityGroup.objects.exists() or CommunityTask.objects.exists():
            raise CommandError('Verification fixtures already exist; use their existing accounts.')
        User = get_user_model()
        users = {}
        for index, name in enumerate(('Owner', 'Admin', 'Member', 'Outside', 'Pending')):
            user = User.objects.create_user(email=f'community-{name.lower()}@example.test', password=options['password'], name=f'Community {name}', phone=f'+1555000100{index}')
            user.email_verified = True
            user.last_login = timezone.now()
            user.notify_on_new_message = False
            user.notify_on_new_match = False
            user.notify_on_reminders = False
            if name == 'Owner':
                user.is_founder = True
            user.save()
            Profile.objects.get_or_create(user=user, defaults={'bio': 'Local acceptance fixture', 'experience': 'Learning together', 'interests': 'Coding,Reading', 'focus_areas': ['Study & Learning']})
            users[name] = user
        if options.get('avatar_file'):
            with open(options['avatar_file'], 'rb') as image:
                users['Member'].avatar.save('community-verification-avatar.png', File(image))
        category, _ = CommunityCategory.objects.get_or_create(name='Educational')
        group = create_group(users['Owner'], {'name': 'Book club', 'description': 'Read, discuss and turn ideas into shared progress.', 'category': category, 'visibility': 'public'})
        _activate_group(group, users['Admin'], 'admin')
        _activate_group(group, users['Member'])
        _activate_group(group, users['Pending'])
        Message.objects.create(conversation=group.conversation, sender=users['Member'], text='Welcome to the book club. Which chapter should we discuss?')
        task, _ = create_task(users['Owner'], {
            'group': group, 'title': 'Side Quest', 'description': 'Read one chapter each day and share an honest update.',
            'category': 'Educational', 'start_date': timezone.localdate(), 'target_date': timezone.localdate() + timedelta(days=7),
            'invitation_deadline': timezone.now() + timedelta(days=2), 'member_limit': 4, 'visibility': 'private',
            'approval_required': True, 'checkin_frequency': 'DAILY', 'idempotency_key': 'local-verification-side-quest',
            'milestones': [{'title': 'Finish the first chapter', 'due_at': timezone.now() + timedelta(days=1)}, {'title': 'Share what you learned', 'due_at': timezone.now() + timedelta(days=5)}],
        })
        invite_task_users(task, users['Owner'], [users['Member'].id, users['Outside'].id])
        membership = join_task(task, users['Member'], invited=True)
        if membership.state == 'pending':
            decide_task_request(task, users['Owner'], users['Member'], 'approve')
        Message.objects.create(conversation=task.goal.conversation, sender=users['Member'], text='Ready for our first check-in.')
        private = create_group(users['Owner'], {'name': 'Study session', 'description': 'A quiet place for focused learning.', 'category': category, 'visibility': 'private'})
        _activate_group(private, users['Admin'], 'admin')
        self.stdout.write(json.dumps({'group_id': group.id, 'private_group_id': private.id, 'task_id': task.id, 'pod_id': task.goal_id,
                                      'accounts': {key: user.email for key, user in users.items()}}))
