"""Independent cross-route acceptance/security regressions for community launch."""

import base64
import inspect
import tempfile
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier
from unittest.mock import patch

from asgiref.sync import async_to_sync
from channels.db import database_sync_to_async
from channels.layers import get_channel_layer
from channels.routing import URLRouter
from channels.testing import WebsocketCommunicator
from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import close_old_connections
from django.test import TransactionTestCase, override_settings, skipUnlessDBFeature
from django.utils import timezone
from rest_framework.test import APIClient, APITestCase
from knox.models import AuthToken

from accounts.models import User
from .community_models import (
    CommunityCategory, CommunityCreatorApproval, CommunityGroup, CommunityInvite,
    CommunityMembership, CommunityMembershipPeriod, CommunityReport, CommunityTask,
    CommunityTaskMembership, CommunityTaskPeriod,
)
from .community_services import generate_task_cycles, review_inactive_members
from .consumers import ChatConsumer, _ScopeRequest
from .message_models import MessageHidden, MessagePin
from .routing import websocket_urlpatterns
from .models import (
    ContentReport, Conversation, ConversationMembership, Goal, GoalCheckin, GoalMembership,
    Message, Notification, SubTask, Task,
)


TEST_SETTINGS = {
    'SECURE_SSL_REDIRECT': False,
    'EMAIL_NOTIFICATIONS_ENABLED': False,
    'FIREBASE_PUSH_ENABLED': False,
    'PASSWORD_HASHERS': ['django.contrib.auth.hashers.MD5PasswordHasher'],
    'CACHES': {'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache', 'LOCATION': 'community-acceptance'}},
    'CHANNEL_LAYERS': {'default': {'BACKEND': 'channels.layers.InMemoryChannelLayer'}},
}


class CommunityFixtures:
    def setUp(self):
        super().setUp()
        self.media = tempfile.TemporaryDirectory()
        self.addCleanup(self.media.cleanup)
        setting = override_settings(PRIVATE_MEDIA_ROOT=self.media.name, MEDIA_ROOT=self.media.name)
        setting.enable()
        self.addCleanup(setting.disable)
        self.owner = self.user('owner')
        self.admin = self.user('admin')
        self.member = self.user('member')
        self.other = self.user('other')
        self.outsider = self.user('outsider')
        self.internal = self.user('internal', is_staff=True)
        self.category = CommunityCategory.objects.create(name='Acceptance category')
        self.conversation = Conversation.objects.create(is_group=True, name='Acceptance group')
        self.group = CommunityGroup.objects.create(
            creator=self.owner, category=self.category, conversation=self.conversation,
            name='Acceptance group',
        )
        self.admit(self.owner, 'admin')
        self.admit(self.admin, 'admin')
        self.membership = self.admit(self.member)
        self.admit(self.other)
        self.client = APIClient()
        self.client.force_authenticate(self.member)

    def user(self, label, **flags):
        user = User.objects.create_user(
            email=f'acceptance-{label}@test.com', name=label.title(), password='test-password',
        )
        for key, value in flags.items():
            setattr(user, key, value)
        if flags:
            user.save(update_fields=list(flags))
        return user

    def admit(self, user, role='member', joined_at=None):
        joined_at = joined_at or timezone.now()
        membership = CommunityMembership.objects.create(
            group=self.group, user=user, role=role, state='active', joined_at=joined_at,
        )
        CommunityMembershipPeriod.objects.create(membership=membership, joined_at=joined_at)
        ConversationMembership.objects.create(conversation=self.conversation, user=user)
        return membership

    def task(self, **overrides):
        goal = Goal.objects.create(
            user=self.owner, title='Acceptance task', start_date=timezone.localdate(),
            target_date=timezone.localdate() + timedelta(days=10), checkin_frequency='DAILY',
        )
        conversation, _ = Conversation.objects.get_or_create(goal=goal, defaults={'is_group': True})
        task = CommunityTask.objects.create(
            group=self.group, goal=goal, creator=self.owner,
            idempotency_key=f'fixture-{goal.pk}', invitation_deadline=timezone.now() + timedelta(days=2),
            **overrides,
        )
        self.admit_pod(task, self.owner, 'admin')
        return task

    def admit_pod(self, task, user, role='member', joined_at=None):
        membership = CommunityTaskMembership.objects.create(
            task=task, user=user, role=role, state='active', joined_at=joined_at or timezone.now(),
        )
        CommunityTaskPeriod.objects.create(membership=membership, joined_at=membership.joined_at)
        GoalMembership.objects.update_or_create(goal=task.goal, user=user, defaults={'role': role})
        ConversationMembership.objects.get_or_create(conversation=task.goal.conversation, user=user)
        return membership

    def task_payload(self, **overrides):
        payload = {
            'group': self.group.pk, 'title': 'New acceptance task', 'description': 'Details',
            'category': 'Learning', 'start_date': timezone.localdate().isoformat(),
            'target_date': (timezone.localdate() + timedelta(days=10)).isoformat(),
            'invitation_deadline': (timezone.now() + timedelta(days=2)).isoformat(),
            'member_limit': 8, 'visibility': 'public', 'approval_required': False,
            'checkin_frequency': 'DAILY', 'milestones': [], 'invited_user_ids': [],
            'idempotency_key': 'acceptance-retry',
        }
        payload.update(overrides)
        return payload

    def message(self, text='Visible message', at=None, attachment=False, conversation=None, **fields):
        message = Message.objects.create(
            conversation=conversation or self.conversation, sender=self.owner, text=text,
            attachment=SimpleUploadedFile('acceptance.pdf', b'%PDF-acceptance', content_type='application/pdf') if attachment else None,
            attachment_name='acceptance.pdf' if attachment else '',
            attachment_mime='application/pdf' if attachment else '', **fields,
        )
        if at:
            Message.objects.filter(pk=message.pk).update(created_at=at)
            message.refresh_from_db()
        return message

    def rows(self, response):
        self.assertEqual(response.status_code, 200, getattr(response, 'data', None))
        return response.data['results'] if isinstance(response.data, dict) else response.data

    def denied(self, response):
        self.assertIn(response.status_code, (403, 404), getattr(response, 'data', None))

    def socket(self, user=None, conversation=None):
        consumer = ChatConsumer()
        consumer.scope = {'user': user or self.member, 'headers': []}
        consumer.conversation_id = (conversation or self.conversation).pk
        consumer.serializer_request = _ScopeRequest(consumer.scope)
        return consumer

    def socket_call(self, consumer, method, *args):
        # Exercise the socket's database boundary within the test transaction.
        return inspect.unwrap(getattr(ChatConsumer, method))(consumer, *args)


@override_settings(**TEST_SETTINGS)
class CommunityAcceptanceTests(CommunityFixtures, APITestCase):
    def test_each_internal_flag_works_independently_and_revocation_is_immediate(self):
        for flag in ('is_superuser', 'is_staff', 'is_founder'):
            with self.subTest(flag=flag):
                user = self.user(flag, **{flag: True})
                self.client.force_authenticate(user)
                context = self.client.get('/api-v1/community/groups/context/')
                self.assertTrue(context.data['is_internal'])
                self.assertEqual(self.client.get('/api-v1/community/hq/overview/').status_code, 200)
                setattr(user, flag, False)
                user.save(update_fields=[flag])
                self.denied(self.client.get('/api-v1/community/hq/overview/'))

    def test_approved_creator_never_inherits_hq_privileges(self):
        CommunityCreatorApproval.objects.create(user=self.member, approved_by=self.internal)
        context = self.client.get('/api-v1/community/groups/context/').data
        self.assertTrue(context['can_create'])
        self.assertFalse(context['is_internal'])
        self.assertNotIn('hq', str(context).lower())
        for path in ('overview', 'users'):
            self.assertEqual(self.client.get(f'/api-v1/community/hq/{path}/').status_code, 404)
        self.assertEqual(self.client.post('/api-v1/community/hq/approve-creator/', {
            'user_id': self.outsider.pk, 'approved': True,
        }, format='json').status_code, 404)
        self.denied(self.client.patch(f'/api-v1/community/groups/{self.group.pk}/', {'name': 'Hijacked'}, format='json'))

    def test_unapproved_creation_and_forged_internal_fields_are_rejected(self):
        payload = {'name': 'Unauthorized', 'description': '', 'category': self.category.pk,
                   'visibility': 'public', 'is_internal': True, 'is_staff': True}
        self.denied(self.client.post('/api-v1/community/groups/', payload, format='json'))
        self.assertFalse(CommunityGroup.objects.filter(name='Unauthorized').exists())

    def test_one_admin_group_blocks_join_until_second_admin_accepts(self):
        CommunityMembership.objects.filter(group=self.group, user=self.admin).update(role='member')
        self.client.force_authenticate(self.outsider)
        response = self.client.post(f'/api-v1/community/groups/{self.group.pk}/join/', {}, format='json')
        self.assertEqual(response.status_code, 400, response.data)
        self.client.force_authenticate(self.owner)
        invitation = self.client.post(f'/api-v1/community/groups/{self.group.pk}/members/', {
            'user_id': self.outsider.pk, 'action': 'invite', 'role': 'admin',
        }, format='json')
        self.assertEqual(invitation.status_code, 201, invitation.data)
        self.assertFalse(CommunityMembership.objects.filter(group=self.group, user=self.outsider, state='active').exists())
        self.client.force_authenticate(self.outsider)
        accepted = self.client.post(f'/api-v1/community/groups/{self.group.pk}/join/', {
            'token': invitation.data['token'],
        }, format='json')
        self.assertEqual(accepted.status_code, 200, accepted.data)
        self.assertEqual(CommunityMembership.objects.get(group=self.group, user=self.outsider).role, 'admin')
        self.assertFalse(accepted.data['joins_paused'])

    def test_admin_shortage_notifies_but_does_not_freeze_existing_chat(self):
        self.client.force_authenticate(self.owner)
        response = self.client.post(f'/api-v1/community/groups/{self.group.pk}/members/', {
            'user_id': self.admin.pk, 'action': 'role', 'role': 'member',
        }, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        self.assertTrue(Notification.objects.filter(user=self.owner, type='community_admin_required').exists())
        self.client.force_authenticate(self.member)
        response = self.client.post('/api-v1/messages/', {'conversation': self.conversation.pk, 'text': 'Still active'}, format='json')
        self.assertEqual(response.status_code, 201, response.data)

    def test_private_generic_invite_requires_approval_and_no_legacy_content_access(self):
        self.group.visibility = 'private'
        self.group.save()
        invitation = CommunityInvite.objects.create(
            group=self.group, invited_by=self.owner, expires_at=timezone.now() + timedelta(days=7),
        )
        secret = self.message()
        self.client.force_authenticate(self.outsider)
        response = self.client.post(f'/api-v1/community/groups/{self.group.pk}/join/', {'token': str(invitation.token)}, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(CommunityMembership.objects.get(group=self.group, user=self.outsider).state, 'pending')
        for path in (f'/api-v1/messages/{secret.pk}/', f'/api-v1/conversations/{self.conversation.pk}/',
                     f'/api-v1/community/groups/{self.group.pk}/resources/?type=files'):
            self.denied(self.client.get(path))
        self.assertEqual(self.rows(self.client.get('/api-v1/community/messages/', {'conversation': self.conversation.pk})), [])

    def test_malformed_or_expired_group_tokens_never_join_or_raise_server_errors(self):
        expired = CommunityInvite.objects.create(
            group=self.group, invited_by=self.owner, expires_at=timezone.now() - timedelta(seconds=1),
        )
        self.client.force_authenticate(self.outsider)
        self.client.raise_request_exception = False
        for token in ('not-a-uuid', str(expired.token)):
            with self.subTest(token=token):
                response = self.client.post(f'/api-v1/community/groups/{self.group.pk}/join/', {'token': token}, format='json')
                self.assertEqual(response.status_code, 400)
        self.assertFalse(CommunityMembership.objects.filter(group=self.group, user=self.outsider, state='active').exists())

    def test_exact_30_day_boundary_full_old_resources_and_sanitized_reply(self):
        boundary = self.membership.joined_at - timedelta(days=30)
        before = self.message(text='Forbidden pre-window body', at=boundary - timedelta(microseconds=1), attachment=True)
        at = self.message(at=boundary)
        reply = self.message(reply_to_message=before, is_a_reply=True)
        MessagePin.objects.create(message=before, pinned_by=self.owner)
        for prefix in ('/api-v1/messages/', '/api-v1/community/messages/'):
            ids = {row['id'] for row in self.rows(self.client.get(prefix, {'conversation': self.conversation.pk}))}
            self.assertNotIn(before.pk, ids)
            self.assertIn(at.pk, ids)
            self.assertIsNone(self.client.get(f'{prefix}{reply.pk}/').data['reply_to'])
        for kind in ('files', 'pins'):
            rows = self.rows(self.client.get(f'/api-v1/community/groups/{self.group.pk}/resources/', {'type': kind}))
            old = next(row for row in rows if row['id'] == before.pk)
            self.assertEqual(old['text'], '')
            self.assertEqual(old['metadata'], {})
            self.assertIsNone(old['reply_to'])
        response = self.client.get(f'/api-v1/community/messages/{before.pk}/attachment/')
        self.assertEqual(response.status_code, 200)
        self.assertIn('no-store', response['Cache-Control'])
        b''.join(response.streaming_content)

    def test_voluntary_leave_blocks_new_content_rest_and_socket_helpers(self):
        prior = self.message(attachment=True)
        response = self.client.post(f'/api-v1/community/groups/{self.group.pk}/leave/', {'reason': 'Goals achieved'}, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        later = self.message(text='After departure', attachment=True)
        self.assertEqual(self.client.get(f'/api-v1/messages/{prior.pk}/').status_code, 200)
        for path in (f'/api-v1/messages/{later.pk}/', f'/api-v1/community/messages/{later.pk}/attachment/'):
            self.denied(self.client.get(path))
        files = self.rows(self.client.get(f'/api-v1/community/groups/{self.group.pk}/resources/', {'type': 'files'}))
        self.assertEqual({row['id'] for row in files}, {prior.pk})
        for prefix in ('/api-v1/messages/', '/api-v1/community/messages/'):
            self.denied(self.client.post(prefix, {'conversation': self.conversation.pk, 'text': 'Forbidden'}, format='json'))
        consumer = self.socket()
        history = self.socket_call(consumer, 'get_message_history', self.conversation.pk, self.member.pk)
        self.assertEqual({row['id'] for row in history}, {prior.pk})
        with self.assertRaises(PermissionError):
            self.socket_call(consumer, 'create_message', self.member.pk, self.conversation.pk, 'Forbidden')

    def test_rejoining_does_not_disclose_absence_period(self):
        self.client.post(f'/api-v1/community/groups/{self.group.pk}/leave/', {'reason': 'Break'}, format='json')
        gap = self.message(text='During absence', attachment=True)
        response = self.client.post(f'/api-v1/community/groups/{self.group.pk}/join/', {}, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        current = self.message(text='After return', attachment=True)
        self.denied(self.client.get(f'/api-v1/messages/{gap.pk}/'))
        rows = self.rows(self.client.get(f'/api-v1/community/groups/{self.group.pk}/resources/', {'type': 'files'}))
        self.assertEqual({row['id'] for row in rows}, {current.pk})

    def test_removed_group_member_loses_all_history_but_not_existing_pod(self):
        task = self.task()
        self.admit_pod(task, self.member)
        message = self.message(attachment=True)
        self.client.force_authenticate(self.owner)
        response = self.client.post(f'/api-v1/community/groups/{self.group.pk}/members/', {
            'user_id': self.member.pk, 'action': 'ban', 'reason': 'Repeated harassment',
        }, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        self.client.force_authenticate(self.member)
        for path in (f'/api-v1/messages/{message.pk}/', f'/api-v1/community/messages/{message.pk}/attachment/',
                     f'/api-v1/community/groups/{self.group.pk}/resources/?type=files'):
            self.denied(self.client.get(path))
        self.assertEqual(self.client.get(f'/api-v1/goals/{task.goal_id}/').status_code, 200)
        consumer = self.socket()
        self.assertFalse(self.socket_call(consumer, 'user_in_conversation', self.member.pk, self.conversation.pk))
        self.assertEqual(self.socket_call(consumer, 'get_message_history', self.conversation.pk, self.member.pk), [])

    def test_group_leaver_cannot_discover_later_tasks_without_group_filter_or_by_id(self):
        self.client.post(f'/api-v1/community/groups/{self.group.pk}/leave/', {'reason': 'Break'}, format='json')
        task = self.task()
        rows = self.rows(self.client.get('/api-v1/community/tasks/'))
        self.assertNotIn(task.pk, {row['id'] for row in rows})
        self.denied(self.client.get(f'/api-v1/community/tasks/{task.pk}/'))

    def test_owner_invitation_does_not_auto_accept_or_join_source_group(self):
        task = self.task(visibility='private')
        self.client.force_authenticate(self.owner)
        invited = self.client.post(f'/api-v1/community/tasks/{task.pk}/invitations/', {'user_ids': [self.outsider.pk]}, format='json')
        self.assertEqual(invited.status_code, 200, invited.data)
        self.assertFalse(task.goal.members.filter(pk=self.outsider.pk).exists())
        self.client.force_authenticate(self.outsider)
        for path in (f'/api-v1/goals/{task.goal_id}/', f'/api-v1/conversations/{task.goal.conversation.pk}/'):
            self.denied(self.client.get(path))
        accepted = self.client.post(f'/api-v1/community/tasks/{task.pk}/respond/', {'decision': 'accept'}, format='json')
        self.assertEqual(accepted.status_code, 200, accepted.data)
        self.assertEqual(accepted.data['member_count'], 2)
        self.assertFalse(CommunityMembership.objects.filter(group=self.group, user=self.outsider).exists())
        self.denied(self.client.get(f'/api-v1/community/groups/{self.group.pk}/members/'))
        self.assertEqual(self.client.get(f'/api-v1/goals/{task.goal_id}/').status_code, 200)

    def test_private_task_request_cannot_be_self_approved_or_read_pod(self):
        task = self.task(visibility='private')
        response = self.client.post(f'/api-v1/community/tasks/{task.pk}/join/', {}, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(CommunityTaskMembership.objects.get(task=task, user=self.member).state, 'pending')
        self.denied(self.client.get(f'/api-v1/goals/{task.goal_id}/'))
        self.denied(self.client.post(f'/api-v1/community/tasks/{task.pk}/requests/', {
            'user_id': self.member.pk, 'decision': 'approve',
        }, format='json'))

    def test_private_approval_cannot_overbook_or_create_orphan_legacy_membership(self):
        task = self.task(visibility='private', member_limit=2)
        for user in (self.member, self.other):
            self.client.force_authenticate(user)
            response = self.client.post(f'/api-v1/community/tasks/{task.pk}/join/', {}, format='json')
            self.assertEqual(response.status_code, 200, response.data)
        self.client.force_authenticate(self.owner)
        url = f'/api-v1/community/tasks/{task.pk}/requests/'
        approved = self.client.post(url, {'user_id': self.member.pk, 'decision': 'approve'}, format='json')
        self.assertEqual(approved.status_code, 200, approved.data)
        denied = self.client.post(url, {'user_id': self.other.pk, 'decision': 'approve'}, format='json')
        self.assertEqual(denied.status_code, 400, denied.data)
        self.assertEqual(task.memberships.filter(state='active').count(), 2)
        self.assertFalse(GoalMembership.objects.filter(goal=task.goal, user=self.other).exists())
        self.assertFalse(ConversationMembership.objects.filter(conversation=task.goal.conversation, user=self.other).exists())

    def test_capacity_includes_creator_and_duplicate_join_does_not_consume_slot(self):
        task = self.task(member_limit=2)
        url = f'/api-v1/community/tasks/{task.pk}/join/'
        for _ in range(2):
            response = self.client.post(url, {}, format='json')
            self.assertEqual(response.status_code, 200, response.data)
            self.assertEqual(response.data['member_count'], 2)
        self.client.force_authenticate(self.other)
        self.assertEqual(self.client.post(url, {}, format='json').status_code, 400)
        self.assertEqual(task.memberships.filter(state='active').count(), 2)
        self.assertEqual(task.memberships.filter(role='admin', state='active').count(), 1)

    def test_duplicate_creation_creates_exactly_one_goal_pod_card_and_owner(self):
        payload = self.task_payload()
        responses = [self.client.post('/api-v1/community/tasks/', payload, format='json') for _ in range(2)]
        self.assertEqual([response.status_code for response in responses], [201, 200])
        self.assertEqual(responses[0].data['id'], responses[1].data['id'])
        task = CommunityTask.objects.get(pk=responses[0].data['id'])
        self.assertEqual(Conversation.objects.filter(goal=task.goal).count(), 1)
        self.assertEqual(task.memberships.filter(state='active').count(), 1)
        self.assertEqual(Message.objects.filter(conversation=self.conversation, metadata__community_task_id=task.pk).count(), 1)

    def test_failed_task_creation_rolls_back_goal_pod_and_memberships(self):
        counts = (Goal.objects.count(), Conversation.objects.count(), CommunityTask.objects.count())
        with patch('api.community_services.generate_task_cycles', side_effect=RuntimeError('Injected scheduling failure')):
            with self.assertRaisesRegex(RuntimeError, 'Injected scheduling failure'):
                self.client.post('/api-v1/community/tasks/', self.task_payload(), format='json')
        self.assertEqual(counts, (Goal.objects.count(), Conversation.objects.count(), CommunityTask.objects.count()))
        self.assertFalse(Message.objects.filter(metadata__event='community_task_created').exists())

    def test_ordinary_creator_cannot_forge_capacity_or_duration_override(self):
        for extra in ({'member_limit': 9}, {'target_date': (timezone.localdate() + timedelta(days=15)).isoformat()}):
            with self.subTest(extra=extra):
                payload = self.task_payload(limits_approval_reason='Claiming approval', limits_approved_by=self.internal.pk, **extra)
                self.assertEqual(self.client.post('/api-v1/community/tasks/', payload, format='json').status_code, 400)

    def test_group_delete_preserves_pod_but_blocks_new_group_activity(self):
        task = self.task()
        self.admit_pod(task, self.member)
        old = self.message(attachment=True)
        self.client.force_authenticate(self.owner)
        response = self.client.post(f'/api-v1/community/groups/{self.group.pk}/lifecycle/', {'status': 'deleted', 'reason': 'Closing group'}, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        self.client.force_authenticate(self.member)
        self.assertEqual(self.client.get(f'/api-v1/messages/{old.pk}/').status_code, 200)
        self.denied(self.client.post('/api-v1/messages/', {'conversation': self.conversation.pk, 'text': 'No'}, format='json'))
        posted = self.client.post('/api-v1/messages/', {'conversation': task.goal.conversation.pk, 'text': 'Pod continues'}, format='json')
        self.assertEqual(posted.status_code, 201, posted.data)
        task.refresh_from_db()
        self.assertEqual(task.status, 'active')
        self.denied(self.client.post('/api-v1/community/tasks/', self.task_payload(), format='json'))
        self.client.force_authenticate(self.outsider)
        self.assertNotIn(self.group.pk, {row['id'] for row in self.rows(self.client.get('/api-v1/community/groups/'))})

    def test_task_chat_post_deletion_does_not_archive_task(self):
        created = self.client.post('/api-v1/community/tasks/', self.task_payload(), format='json')
        self.assertEqual(created.status_code, 201, created.data)
        task = CommunityTask.objects.get(pk=created.data['id'])
        card = Message.objects.get(conversation=self.conversation, metadata__community_task_id=task.pk)
        self.client.force_authenticate(self.owner)
        deleted = self.client.post('/api-v1/community/messages/delete-selection/', {
            'ids': [card.pk], 'scope': 'everyone', 'reason': 'Remove announcement only',
        }, format='json')
        self.assertEqual(deleted.status_code, 200, deleted.data)
        task.refresh_from_db()
        self.assertEqual(task.status, 'active')
        self.assertTrue(task.goal.is_active)

    def test_task_deletion_is_read_only_and_never_generates_more_cycles(self):
        task = self.task()
        self.admit_pod(task, self.member)
        old = self.message(conversation=task.goal.conversation)
        self.client.force_authenticate(self.owner)
        response = self.client.post(f'/api-v1/community/tasks/{task.pk}/lifecycle/', {'status': 'deleted', 'reason': 'Task removed'}, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        task.refresh_from_db()
        self.assertEqual(task.status, 'archived')
        self.assertEqual(generate_task_cycles(task, now=timezone.now() + timedelta(days=3)), 0)
        self.assertEqual(self.client.get(f'/api-v1/messages/{old.pk}/').status_code, 200)
        self.denied(self.client.post('/api-v1/messages/', {'conversation': task.goal.conversation.pk, 'text': 'No'}, format='json'))

    def test_archived_pod_legacy_milestone_writes_are_denied(self):
        task = self.task(status='archived')
        milestone = Task.objects.create(goal=task.goal, owner=self.owner, title='Read-only milestone')
        self.client.force_authenticate(self.owner)
        self.denied(self.client.patch(f'/api-v1/tasks/{milestone.pk}/', {'title': 'Changed'}, format='json'))
        response = self.client.post('/api-v1/tasks/', {'goal': task.goal_id, 'title': 'New milestone'}, format='json')
        self.assertIn(response.status_code, (400, 403, 404), response.data)
        self.assertFalse(Task.objects.filter(goal=task.goal, title='New milestone').exists())
        self.denied(self.client.post(f'/api-v1/tasks/{milestone.pk}/start_timer/', {}, format='json'))

    def test_removed_milestone_owner_cannot_use_legacy_owner_routes(self):
        task = self.task()
        self.admit_pod(task, self.member)
        milestone = Task.objects.create(goal=task.goal, owner=self.member, title='Revoked milestone')
        subtask = SubTask.objects.create(task=milestone, owner=self.member, title='Revoked subtask')
        self.client.force_authenticate(self.owner)
        removed = self.client.post(f'/api-v1/community/tasks/{task.pk}/members/', {
            'user_id': self.member.pk, 'action': 'remove', 'reason': 'Unsafe conduct',
        }, format='json')
        self.assertEqual(removed.status_code, 200, removed.data)
        self.client.force_authenticate(self.member)
        for path in (f'/api-v1/tasks/{milestone.pk}/', f'/api-v1/subtasks/{subtask.pk}/'):
            self.denied(self.client.get(path))
            self.denied(self.client.patch(path, {'title': 'Retained access'}, format='json'))

    def test_moderation_still_works_when_text_posting_is_disabled(self):
        old = self.message(at=timezone.now() - timedelta(days=2))
        self.group.post_permissions['text'] = False
        self.group.save()
        self.client.force_authenticate(self.admin)
        response = self.client.post('/api-v1/community/messages/delete-selection/', {
            'ids': [old.pk], 'scope': 'everyone', 'reason': 'Abusive content',
        }, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        old.refresh_from_db()
        self.assertEqual(old.deletion_kind, 'moderator')

    def test_cross_conversation_bulk_selection_never_partially_hides(self):
        own = self.message()
        private = Conversation.objects.create(is_group=False)
        foreign = self.message(conversation=private)
        for scope in ('me', 'everyone'):
            with self.subTest(scope=scope):
                response = self.client.post('/api-v1/community/messages/delete-selection/', {
                    'ids': [own.pk, foreign.pk], 'scope': scope, 'reason': 'Cannot bridge scope',
                }, format='json')
                self.denied(response)
                self.assertFalse(MessageHidden.objects.filter(message=own, user=self.member).exists())
                own.refresh_from_db()
                self.assertIsNone(own.recalled_at)

    def test_sender_recall_includes_exact_15_minutes_but_not_one_microsecond_later(self):
        now = timezone.now()
        exact = Message.objects.create(conversation=self.conversation, sender=self.member, text='At boundary')
        expired = Message.objects.create(conversation=self.conversation, sender=self.member, text='Expired')
        Message.objects.filter(pk=exact.pk).update(created_at=now - timedelta(minutes=15))
        Message.objects.filter(pk=expired.pk).update(created_at=now - timedelta(minutes=15, microseconds=1))
        with patch('api.community_messaging.timezone.now', return_value=now):
            response = self.client.post('/api-v1/community/messages/delete-selection/', {'ids': [exact.pk], 'scope': 'everyone'}, format='json')
            self.assertEqual(response.status_code, 200, response.data)
            self.denied(self.client.post('/api-v1/community/messages/delete-selection/', {'ids': [expired.pk], 'scope': 'everyone'}, format='json'))
        expired.refresh_from_db()
        self.assertIsNone(expired.recalled_at)

    def test_deleted_attachment_never_survives_reply_pins_or_legacy_media(self):
        original = self.message(attachment=True)
        reply = self.message(reply_to_message=original, is_a_reply=True)
        MessagePin.objects.create(message=original, pinned_by=self.owner)
        self.client.force_authenticate(self.owner)
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post('/api-v1/community/messages/delete-selection/', {'ids': [original.pk], 'scope': 'everyone'}, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        self.client.force_authenticate(self.member)
        rendered = self.client.get(f'/api-v1/messages/{reply.pk}/').data['reply_to']
        self.assertEqual(rendered['text'], 'This message was deleted')
        self.assertIsNone(rendered['attachment'])
        self.assertEqual(rendered['attachment_name'], '')
        for kind in ('files', 'pins'):
            ids = {row['id'] for row in self.rows(self.client.get(f'/api-v1/community/groups/{self.group.pk}/resources/', {'type': kind}))}
            self.assertNotIn(original.pk, ids)
        self.denied(self.client.get(f'/api-v1/community/messages/{original.pk}/attachment/'))

    def test_post_permissions_apply_to_both_rest_routes_and_socket_uploads(self):
        self.group.post_permissions.update(document=False, link=False)
        self.group.save()
        for prefix in ('/api-v1/messages/', '/api-v1/community/messages/'):
            self.denied(self.client.post(prefix, {'conversation': self.conversation.pk, 'text': 'https://example.com'}, format='json'))
            self.denied(self.client.post(prefix, {
                'conversation': self.conversation.pk,
                'attachment': SimpleUploadedFile('blocked.pdf', b'%PDF', content_type='application/pdf'),
            }, format='multipart'))
        consumer = self.socket()
        with self.assertRaises(PermissionError):
            self.socket_call(consumer, 'create_message', self.member.pk, self.conversation.pk, 'https://example.com')

    def test_platform_ban_revokes_existing_rest_and_socket_context(self):
        task = self.task()
        self.admit_pod(task, self.member)
        message = self.message()
        consumer = self.socket()
        self.member.is_active = False
        self.member.save(update_fields=['is_active'])
        for path in (f'/api-v1/messages/{message.pk}/', f'/api-v1/conversations/{self.conversation.pk}/', f'/api-v1/goals/{task.goal_id}/'):
            self.denied(self.client.get(path))
        self.assertFalse(self.socket_call(consumer, 'user_in_conversation', self.member.pk, self.conversation.pk))
        self.assertIsNone(self.socket_call(consumer, 'serialize_message', message.pk))
        with self.assertRaises(PermissionError):
            self.socket_call(consumer, 'create_message', self.member.pk, self.conversation.pk, 'Stale token')

    def test_inactivity_only_flags_and_notifies_never_removes(self):
        task = self.task()
        self.admit_pod(task, self.member)
        self.member.last_login = timezone.now() - timedelta(days=28, minutes=1)
        self.member.save(update_fields=['last_login'])
        self.assertEqual(review_inactive_members(), 2)
        self.assertEqual(review_inactive_members(), 0)
        self.membership.refresh_from_db()
        self.assertEqual(self.membership.state, 'active')
        self.assertEqual(task.memberships.get(user=self.member).state, 'active')
        self.assertEqual(Notification.objects.filter(user=self.member, type='community_inactivity_review').count(), 2)

    def test_group_notification_mute_suppresses_new_message_notifications(self):
        response = self.client.post(f'/api-v1/community/groups/{self.group.pk}/preferences/', {
            'notifications_muted': True,
        }, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        self.client.force_authenticate(self.owner)
        with patch('api.signals.get_globally_online_user_ids', return_value=set()), patch('api.signals.get_online_user_ids', return_value=set()):
            posted = self.client.post('/api-v1/messages/', {
                'conversation': self.conversation.pk, 'text': 'Muted group update',
            }, format='json')
        self.assertEqual(posted.status_code, 201, posted.data)
        self.assertFalse(Notification.objects.filter(user=self.member, type='new_message', payload__message_id=posted.data['id']).exists())

    def test_stale_legacy_membership_cannot_leak_removed_group_content_via_notification(self):
        self.membership.state = 'removed'
        self.membership.save(update_fields=['state'])
        self.client.force_authenticate(self.owner)
        with patch('api.signals.get_globally_online_user_ids', return_value=set()), patch('api.signals.get_online_user_ids', return_value=set()):
            posted = self.client.post('/api-v1/messages/', {
                'conversation': self.conversation.pk, 'text': 'Secret after removal',
            }, format='json')
        self.assertEqual(posted.status_code, 201, posted.data)
        self.assertFalse(Notification.objects.filter(user=self.member, type='new_message', payload__message_id=posted.data['id']).exists())

    def test_removed_group_user_cannot_read_prior_message_preview_in_notifications(self):
        self.client.force_authenticate(self.owner)
        with patch('api.signals.get_globally_online_user_ids', return_value=set()), patch('api.signals.get_online_user_ids', return_value=set()):
            posted = self.client.post('/api-v1/messages/', {
                'conversation': self.conversation.pk, 'text': 'Sensitive pre-removal preview',
            }, format='json')
        self.assertEqual(posted.status_code, 201, posted.data)
        notification = Notification.objects.get(user=self.member, type='new_message', payload__message_id=posted.data['id'])
        removed = self.client.post(f'/api-v1/community/groups/{self.group.pk}/members/', {
            'user_id': self.member.pk, 'action': 'remove', 'reason': 'Group access revoked',
        }, format='json')
        self.assertEqual(removed.status_code, 200, removed.data)
        self.client.force_authenticate(self.member)
        rows = self.rows(self.client.get('/api-v1/notifications/'))
        with self.subTest(surface='notification list'):
            self.assertNotIn('Sensitive pre-removal preview', str(rows))
        direct = self.client.get(f'/api-v1/notifications/{notification.pk}/')
        with self.subTest(surface='direct notification ID'):
            if direct.status_code == 200:
                self.assertNotIn('Sensitive pre-removal preview', str(direct.data))
            else:
                self.denied(direct)

    def test_group_admin_without_pod_membership_cannot_review_or_view_evidence(self):
        task = self.task()
        checkin = GoalCheckin.objects.create(
            goal=task.goal, user=self.owner, scheduled_for=timezone.localdate(), submitted_at=timezone.now(),
            status='partial', completion_percent=0,
            evidence=SimpleUploadedFile('proof.pdf', b'%PDF', content_type='application/pdf'),
        )
        self.client.force_authenticate(self.admin)
        self.denied(self.client.get(f'/api-v1/checkins/{checkin.pk}/evidence/'))
        self.denied(self.client.post(f'/api-v1/checkins/{checkin.pk}/review/', {'approved': True}, format='json'))
        self.assertFalse(GoalCheckin.objects.filter(pk=checkin.pk, reviewer=self.admin).exists())

    def test_internal_report_evidence_is_scoped_to_report_not_private_chat(self):
        private = Conversation.objects.create()
        for user in (self.owner, self.other):
            ConversationMembership.objects.create(conversation=private, user=user)
        context = self.message(text='Unreported private context', conversation=private)
        reported = self.message(
            text='Reported private content', attachment=True, conversation=private,
            reply_to_message=context, is_a_reply=True,
        )
        report = ContentReport.objects.create(
            reporter=self.other, reported_user=self.owner, message=reported,
            conversation=private, reason='spam',
        )
        self.denied(self.client.get(f'/api-v1/community/messages/{reported.pk}/report-evidence/'))
        self.client.force_authenticate(self.internal)
        for path in (f'/api-v1/conversations/{private.pk}/', f'/api-v1/messages/{reported.pk}/',
                     f'/api-v1/community/messages/{reported.pk}/attachment/',
                     f'/api-v1/community/messages/{context.pk}/report-evidence/'):
            self.denied(self.client.get(path))
        url = f'/api-v1/community/messages/{reported.pk}/report-evidence/'
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data['text'], 'Reported private content')
        self.assertIsNone(response.data['reply_to'])
        self.assertIn('report-evidence/?file=1', response.data['attachment'])
        download = self.client.get(url, {'file': '1'})
        self.assertEqual(download.status_code, 200)
        self.assertIn('no-store', download['Cache-Control'])
        b''.join(download.streaming_content)
        report.status = 'dismissed'
        report.save(update_fields=['status'])
        self.denied(self.client.get(url))
        self.denied(self.client.get(url, {'file': '1'}))

    def test_internal_hq_removal_of_reported_private_message_is_target_scoped(self):
        private = Conversation.objects.create()
        for user in (self.owner, self.other):
            ConversationMembership.objects.create(conversation=private, user=user)
        unrelated = self.message(text='Unreported private message', conversation=private)
        reported = self.message(text='Reported abuse', conversation=private)
        report = ContentReport.objects.create(
            reporter=self.other, reported_user=self.owner, message=reported,
            conversation=private, reason='harassment',
        )
        self.client.force_authenticate(self.internal)
        overview = self.client.get('/api-v1/community/hq/overview/')
        self.assertEqual(overview.status_code, 200, overview.data)
        report_id = next(row['id'] for row in overview.data['reports'] if row['content_report_id'] == report.pk)
        response = self.client.post('/api-v1/community/hq/review-report/', {
            'report_id': report_id, 'status': 'actioned', 'action': 'remove_message',
            'notes': 'Reviewed the reported content', 'reason': 'Harassment confirmed',
        }, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        reported.refresh_from_db()
        unrelated.refresh_from_db()
        self.assertEqual(reported.deletion_kind, 'moderator')
        self.assertEqual(reported.deleted_by_id, self.internal.pk)
        self.assertIsNone(unrelated.recalled_at)
        self.denied(self.client.get(f'/api-v1/messages/{unrelated.pk}/'))

    def test_voluntary_pod_leaver_can_read_summary_but_cannot_view_evidence_or_review(self):
        task = self.task()
        self.admit_pod(task, self.member)
        checkin = GoalCheckin.objects.create(
            goal=task.goal, user=self.owner, scheduled_for=timezone.localdate(), submitted_at=timezone.now(),
            status='partial', completion_percent=0,
            evidence=SimpleUploadedFile('proof.pdf', b'%PDF', content_type='application/pdf'),
        )
        self.client.post(f'/api-v1/community/tasks/{task.pk}/leave/', {'reason': 'Done'}, format='json')
        self.assertEqual(self.client.get(f'/api-v1/checkins/{checkin.pk}/').status_code, 200)
        self.denied(self.client.get(f'/api-v1/checkins/{checkin.pk}/evidence/'))
        self.denied(self.client.post(f'/api-v1/checkins/{checkin.pk}/review/', {'approved': True}, format='json'))

    def test_members_cannot_delete_system_cycles_or_retained_archived_history(self):
        task = self.task()
        self.admit_pod(task, self.member)
        checkin = GoalCheckin.objects.create(
            goal=task.goal, user=self.owner, scheduled_for=timezone.localdate(), submitted_at=timezone.now(),
            status='partial', completion_percent=0,
            evidence=SimpleUploadedFile('proof.pdf', b'%PDF', content_type='application/pdf'),
        )
        for status in ('active', 'archived'):
            task.status = status
            task.save(update_fields=['status'])
            for actor in (self.member, self.owner):
                with self.subTest(status=status, actor=actor.pk):
                    self.client.force_authenticate(actor)
                    response = self.client.delete(f'/api-v1/checkins/{checkin.pk}/')
                    self.assertIn(response.status_code, (403, 404, 405), response.data)
                    self.assertTrue(GoalCheckin.objects.filter(pk=checkin.pk).exists())


@override_settings(**TEST_SETTINGS)
class CommunityAuditFollowupAcceptanceTests(CommunityFixtures, APITestCase):
    def test_cadence_change_never_backfills_new_past_cycles_on_later_maintenance(self):
        today, now = timezone.localdate(), timezone.now()
        task = self.task()
        task.goal.start_date = today - timedelta(days=7)
        task.goal.checkin_frequency = 'WEEKLY'
        task.goal.save(update_fields=['start_date', 'checkin_frequency'])
        CommunityTaskMembership.objects.filter(task=task).update(joined_at=now - timedelta(days=7))
        CommunityTaskPeriod.objects.filter(membership__task=task).update(joined_at=now - timedelta(days=7))
        submitted = GoalCheckin.objects.create(
            goal=task.goal, user=self.owner, scheduled_for=today - timedelta(days=7),
            submitted_at=now - timedelta(days=7), status='partial', completion_percent=35,
            evidence=SimpleUploadedFile('old-proof.pdf', b'%PDF-old-proof', content_type='application/pdf'),
        )
        issued = GoalCheckin.objects.create(goal=task.goal, user=self.owner, scheduled_for=today)
        future = GoalCheckin.objects.create(goal=task.goal, user=self.owner, scheduled_for=today + timedelta(days=3))
        self.client.force_authenticate(self.owner)
        response = self.client.patch(f'/api-v1/community/tasks/{task.pk}/', {'checkin_frequency': 'DAILY'}, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        self.assertTrue(GoalCheckin.objects.filter(pk=issued.pk).exists())
        self.assertFalse(GoalCheckin.objects.filter(pk=future.pk).exists())
        for maintenance_now in (now, now + timedelta(days=1), now + timedelta(days=4)):
            generate_task_cycles(task, now=maintenance_now)
            historical = task.goal.checkins.filter(scheduled_for__lt=today)
            self.assertEqual(set(historical.values_list('pk', flat=True)), {submitted.pk})
        submitted.refresh_from_db()
        self.assertEqual(submitted.completion_percent, 35)
        self.assertTrue(submitted.evidence.storage.exists(submitted.evidence.name))

        unchanged = self.task()
        unchanged.goal.start_date = today - timedelta(days=7)
        unchanged.goal.save(update_fields=['start_date'])
        CommunityTaskMembership.objects.filter(task=unchanged).update(joined_at=now - timedelta(days=7))
        CommunityTaskPeriod.objects.filter(membership__task=unchanged).update(joined_at=now - timedelta(days=7))
        generate_task_cycles(unchanged, now=now)
        self.assertTrue(unchanged.goal.checkins.filter(scheduled_for=today - timedelta(days=6), status='missed').exists())

    def test_renaming_continuing_pod_never_mutates_deleted_group_history(self):
        task = self.task()
        card = self.message(text=task.goal.title, kind=Message.KIND_GOAL, metadata={
            'community_task_id': task.pk, 'goal_id': task.goal_id, 'event': 'community_task_created',
        })
        original_text, original_updated = card.text, card.updated_at
        self.client.force_authenticate(self.owner)
        deleted = self.client.post(f'/api-v1/community/groups/{self.group.pk}/lifecycle/', {
            'status': 'deleted', 'reason': 'Retain group history',
        }, format='json')
        self.assertEqual(deleted.status_code, 200, deleted.data)
        response = self.client.patch(f'/api-v1/community/tasks/{task.pk}/', {'title': 'Continuing pod renamed'}, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data['title'], 'Continuing pod renamed')
        self.assertEqual(Conversation.objects.get(goal=task.goal).name, 'Continuing pod renamed')
        card.refresh_from_db()
        self.assertEqual(card.text, original_text)
        self.assertEqual(card.updated_at, original_updated)

    def test_inactive_admin_removal_does_not_require_replacing_an_uncounted_admin(self):
        self.admin.is_active = False
        self.admin.save(update_fields=['is_active'])
        self.client.force_authenticate(self.owner)
        response = self.client.post(f'/api-v1/community/groups/{self.group.pk}/members/', {
            'user_id': self.admin.pk, 'action': 'remove', 'reason': 'Remove deactivated admin',
        }, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        membership = CommunityMembership.objects.get(group=self.group, user=self.admin)
        self.assertEqual(membership.state, 'removed')
        self.assertTrue(membership.periods.exclude(ended_at=None).exists())
        self.assertFalse(ConversationMembership.objects.filter(conversation=self.conversation, user=self.admin).exists())
        self.assertEqual(self.client.get(f'/api-v1/community/groups/{self.group.pk}/').data['admin_count'], 1)
        self.admin.is_active = True
        self.admin.save(update_fields=['is_active'])
        self.client.force_authenticate(self.admin)
        self.denied(self.client.get(f'/api-v1/conversations/{self.conversation.pk}/'))

    def test_inactive_pod_member_removal_clears_legacy_access_after_reactivation(self):
        task = self.task()
        membership = self.admit_pod(task, self.member)
        self.member.is_active = False
        self.member.save(update_fields=['is_active'])
        self.client.force_authenticate(self.owner)
        response = self.client.post(f'/api-v1/community/tasks/{task.pk}/members/', {
            'user_id': self.member.pk, 'action': 'remove', 'reason': 'Remove deactivated participant',
        }, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        membership.refresh_from_db()
        self.assertEqual(membership.state, 'removed')
        self.assertTrue(membership.periods.exclude(ended_at=None).exists())
        self.assertFalse(GoalMembership.objects.filter(goal=task.goal, user=self.member).exists())
        self.assertFalse(ConversationMembership.objects.filter(conversation=task.goal.conversation, user=self.member).exists())
        self.member.is_active = True
        self.member.save(update_fields=['is_active'])
        self.client.force_authenticate(self.member)
        self.denied(self.client.get(f'/api-v1/goals/{task.goal_id}/'))
        self.denied(self.client.get(f'/api-v1/conversations/{task.goal.conversation.pk}/'))

    def test_banned_member_filter_is_scoped_and_unavailable_to_ordinary_members(self):
        self.client.force_authenticate(self.owner)
        response = self.client.post(f'/api-v1/community/groups/{self.group.pk}/members/', {
            'user_id': self.member.pk, 'action': 'ban', 'reason': 'Repeated misconduct',
        }, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        response = self.client.get(f'/api-v1/community/groups/{self.group.pk}/members/', {'state': 'banned'})
        self.assertIsInstance(response.data, list)
        banned = self.rows(response)
        self.assertEqual({row['user']['id'] for row in banned}, {self.member.pk})
        self.assertTrue(all(row['state'] == 'banned' for row in banned))
        active = self.rows(self.client.get(f'/api-v1/community/groups/{self.group.pk}/members/'))
        self.assertNotIn(self.member.pk, {row['user']['id'] for row in active})
        self.client.force_authenticate(self.other)
        self.denied(self.client.get(f'/api-v1/community/groups/{self.group.pk}/members/', {'state': 'banned'}))

    def test_group_report_queue_rejects_foreign_ids_and_retained_internal_evidence(self):
        own_message = self.message(text='Own-group reported content')
        own_report = CommunityReport.objects.create(
            group=self.group, message=own_message, reporter=self.member,
            reported_user=self.owner, reason='Own-group report',
        )
        foreign_conversation = Conversation.objects.create(is_group=True)
        foreign_group = CommunityGroup.objects.create(
            creator=self.other, category=self.category, conversation=foreign_conversation, name='Foreign group',
        )
        foreign_message = self.message(text='Foreign private evidence', conversation=foreign_conversation)
        foreign_report = CommunityReport.objects.create(
            group=foreign_group, message=foreign_message, reporter=self.other,
            reported_user=self.owner, reason='Foreign report',
        )
        self.client.force_authenticate(self.owner)
        response = self.client.get(f'/api-v1/community/groups/{self.group.pk}/reports/')
        self.assertEqual(response.status_code, 200, response.data)
        self.assertIsInstance(response.data, dict)
        self.assertTrue({'results', 'count', 'next', 'previous'} <= response.data.keys())
        queue = self.rows(response)
        self.assertEqual({row['id'] for row in queue}, {own_report.pk})
        evidence = f'/api-v1/community/groups/{self.group.pk}/reports/{own_report.pk}/evidence/'
        self.assertEqual(self.client.get(evidence).data['text'], own_message.text)
        self.denied(self.client.get(f'/api-v1/community/groups/{self.group.pk}/reports/{foreign_report.pk}/evidence/'))
        self.denied(self.client.post(f'/api-v1/community/groups/{self.group.pk}/review-report/', {
            'report_id': foreign_report.pk, 'status': 'dismissed', 'notes': 'Cross-group attempt',
        }, format='json'))
        foreign_report.refresh_from_db()
        self.assertEqual(foreign_report.status, 'pending')
        self.client.force_authenticate(self.member)
        self.denied(self.client.get(f'/api-v1/community/groups/{self.group.pk}/reports/'))
        self.denied(self.client.get(evidence))
        self.denied(self.client.post(f'/api-v1/community/groups/{self.group.pk}/review-report/', {
            'report_id': own_report.pk, 'status': 'dismissed',
        }, format='json'))
        self.client.force_authenticate(self.owner)
        deletion = self.client.post('/api-v1/community/messages/delete-selection/', {
            'ids': [own_message.pk], 'scope': 'everyone',
        }, format='json')
        self.assertEqual(deletion.status_code, 200, deletion.data)
        redacted = self.client.get(evidence)
        if redacted.status_code == 200:
            self.assertEqual(redacted.data['text'], 'This message was deleted')
            self.assertIsNone(redacted.data['poll'])
            self.assertIsNone(redacted.data['attachment'])
            self.assertFalse(redacted.data.get('is_retained_evidence', False))
            self.assertNotIn('reports', redacted.data)
        else:
            self.denied(redacted)
        self.client.force_authenticate(self.internal)
        retained = self.client.get(f'/api-v1/community/messages/{own_message.pk}/report-evidence/')
        self.assertEqual(retained.status_code, 200, retained.data)
        self.assertEqual(retained.data['text'], 'Own-group reported content')

    def test_media_only_group_capability_never_grants_text_post_permission(self):
        permissions = dict.fromkeys(self.group.post_permissions, False)
        permissions['image'] = True
        self.client.force_authenticate(self.owner)
        changed = self.client.patch(f'/api-v1/community/groups/{self.group.pk}/', {'post_permissions': permissions}, format='json')
        self.assertEqual(changed.status_code, 200, changed.data)
        self.client.force_authenticate(self.member)
        self.assertTrue(self.client.get(f'/api-v1/community/groups/{self.group.pk}/').data['can_post'])
        for prefix in ('/api-v1/messages/', '/api-v1/community/messages/'):
            self.denied(self.client.post(prefix, {'conversation': self.conversation.pk, 'text': 'Not permitted'}, format='json'))
            uploaded = self.client.post(prefix, {
                'conversation': self.conversation.pk,
                'attachment': SimpleUploadedFile('allowed.png', b'image', content_type='image/png'),
            }, format='multipart')
            self.assertEqual(uploaded.status_code, 201, uploaded.data)
        self.group.post_permissions = dict.fromkeys(permissions, False)
        self.group.save(update_fields=['post_permissions'])
        self.assertFalse(self.client.get(f'/api-v1/community/groups/{self.group.pk}/').data['can_post'])

    def test_deleted_poll_evidence_is_immutable_internal_only_until_all_reports_final(self):
        from django.core.exceptions import ValidationError as DjangoValidationError
        from .message_models import RetainedMessageEvidence

        created = self.client.post('/api-v1/community/messages/', {
            'conversation': self.conversation.pk, 'text': 'Original poll rationale',
            'poll': {'question': 'Original question?', 'options': ['First answer', 'Second answer']},
        }, format='json')
        self.assertEqual(created.status_code, 201, created.data)
        message_id = created.data['id']
        self.client.force_authenticate(self.other)
        voted = self.client.post(f'/api-v1/community/messages/{message_id}/vote/', {
            'option_ids': [created.data['poll']['options'][0]['id']],
        }, format='json')
        self.assertEqual(voted.status_code, 200, voted.data)
        report_ids = []
        for actor, details in ((self.other, 'First original report detail'), (self.owner, 'Second original report detail')):
            self.client.force_authenticate(actor)
            reported = self.client.post(f'/api-v1/community/messages/{message_id}/report/', {'reason': 'spam', 'details': details}, format='json')
            self.assertEqual(reported.status_code, 201, reported.data)
            report_ids.append(ContentReport.objects.get(message_id=message_id, reporter=actor).pk)
        self.client.force_authenticate(self.internal)
        overview = self.client.get('/api-v1/community/hq/overview/')
        self.assertEqual(overview.status_code, 200, overview.data)
        mirrors = [row['id'] for row in overview.data['reports'] if row['content_report_id'] in report_ids]
        self.assertEqual(len(mirrors), 2)
        self.client.force_authenticate(self.owner)
        deleted = self.client.post('/api-v1/community/messages/delete-selection/', {
            'ids': [message_id], 'scope': 'everyone', 'reason': 'Reported poll removal',
        }, format='json')
        self.assertEqual(deleted.status_code, 200, deleted.data)
        ordinary = self.client.get(f'/api-v1/messages/{message_id}/')
        self.assertIsNone(ordinary.data['poll'])
        self.assertEqual(ordinary.data['text'], 'This message was removed by a moderator')
        evidence_url = f'/api-v1/community/messages/{message_id}/report-evidence/'
        self.denied(self.client.get(evidence_url))
        self.client.force_authenticate(self.internal)
        evidence = self.client.get(evidence_url)
        self.assertEqual(evidence.status_code, 200, evidence.data)
        self.assertTrue(evidence.data['is_retained_evidence'])
        self.assertEqual(evidence.data['text'], 'Original poll rationale')
        self.assertEqual(evidence.data['poll']['question'], 'Original question?')
        self.assertEqual(evidence.data['poll']['options'][0]['votes'][0]['id'], self.other.pk)
        self.assertIsNone(evidence.data['reply_to'])
        self.assertIn('First original report detail', str(evidence.data['reports']))
        self.assertIn('Second original report detail', str(evidence.data['reports']))
        self.assertIn('no-store', evidence['Cache-Control'])
        held = RetainedMessageEvidence.objects.get(message_id=message_id)
        held.snapshot['message']['text'] = 'Attempted overwrite'
        with self.assertRaises(DjangoValidationError):
            held.save()
        held.refresh_from_db()
        self.assertEqual(held.snapshot['message']['text'], 'Original poll rationale')
        for index, report_id in enumerate(mirrors):
            resolved = self.client.post('/api-v1/community/hq/review-report/', {
                'report_id': report_id, 'status': 'dismissed', 'notes': 'Final review',
            }, format='json')
            self.assertEqual(resolved.status_code, 200, resolved.data)
            if index == 0:
                self.assertTrue(RetainedMessageEvidence.objects.filter(message_id=message_id).exists())
                self.assertEqual(self.client.get(evidence_url).data['text'], 'Original poll rationale')
        self.assertFalse(RetainedMessageEvidence.objects.filter(message_id=message_id).exists())
        self.denied(self.client.get(evidence_url))
        self.assertTrue(self.group.audit.filter(action='message_removed', target_id=str(message_id)).exists())

    def test_new_group_admin_can_remove_reported_message_older_than_chat_window(self):
        old = self.message(text='Old reported harassment', at=timezone.now() - timedelta(days=40), attachment=True)
        report = CommunityReport.objects.create(
            group=self.group, message=old, reporter=self.member,
            reported_user=self.owner, reason='Reported harassment',
        )
        self.client.force_authenticate(self.admin)
        evidence = self.client.get(f'/api-v1/community/groups/{self.group.pk}/reports/{report.pk}/evidence/')
        self.assertEqual(evidence.status_code, 200, evidence.data)
        self.assertEqual(evidence.data['text'], '')
        self.assertIsNotNone(evidence.data['attachment'])
        response = self.client.post(f'/api-v1/community/groups/{self.group.pk}/review-report/', {
            'report_id': report.pk, 'status': 'actioned', 'action': 'remove_message',
            'reason': 'Old harassment removed', 'notes': 'Review completed',
        }, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        old.refresh_from_db()
        self.assertEqual(old.deletion_kind, 'moderator')
        self.assertEqual(old.deleted_by_id, self.admin.pk)
        self.assertTrue(self.group.audit.filter(action='message_removed', target_id=str(old.pk)).exists())

    def test_new_group_admin_can_remove_old_file_exposed_in_resources_without_report(self):
        old = self.message(text='Old unsafe file', at=timezone.now() - timedelta(days=40), attachment=True)
        self.client.force_authenticate(self.admin)
        response = self.client.get(f'/api-v1/community/groups/{self.group.pk}/resources/', {'type': 'files'})
        resource = next(row for row in self.rows(response) if row['id'] == old.pk)
        self.assertTrue(resource['can_delete_everyone'])
        self.assertTrue(resource['can_moderate'])
        self.assertFalse(ContentReport.objects.filter(message=old).exists())
        self.assertFalse(CommunityReport.objects.filter(message=old).exists())
        storage, name = old.attachment.storage, old.attachment.name
        with self.captureOnCommitCallbacks(execute=True):
            deleted = self.client.post('/api-v1/community/messages/delete-selection/', {
                'ids': [old.pk], 'scope': 'everyone', 'reason': 'Unsafe file removed from resources',
            }, format='json')
        self.assertEqual(deleted.status_code, 200, deleted.data)
        old.refresh_from_db()
        self.assertEqual(old.deletion_kind, 'moderator')
        self.assertFalse(storage.exists(name))


@override_settings(**TEST_SETTINGS)
class CommunityConcurrentEnrollmentTests(CommunityFixtures, TransactionTestCase):
    @skipUnlessDBFeature('has_select_for_update')
    def test_concurrent_last_slot_joins_cannot_overbook(self):
        task = self.task(member_limit=2)
        barrier = Barrier(2)

        def join(user_id):
            close_old_connections()
            try:
                client = APIClient()
                client.force_authenticate(User.objects.get(pk=user_id))
                barrier.wait(timeout=10)
                return client.post(f'/api-v1/community/tasks/{task.pk}/join/', {}, format='json').status_code
            finally:
                close_old_connections()

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(join, [self.member.pk, self.other.pk]))
        self.assertEqual(sorted(results), [200, 400])
        self.assertEqual(task.memberships.filter(state='active').count(), 2)

    @skipUnlessDBFeature('has_select_for_update')
    def test_concurrent_same_key_creation_has_one_pod(self):
        barrier = Barrier(2)
        payload = self.task_payload()

        def create(_):
            close_old_connections()
            try:
                client = APIClient()
                client.force_authenticate(User.objects.get(pk=self.member.pk))
                barrier.wait(timeout=10)
                response = client.post('/api-v1/community/tasks/', payload, format='json')
                return response.status_code, response.data['id']
            finally:
                close_old_connections()

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(create, range(2)))
        self.assertEqual(sorted(status for status, _ in results), [200, 201])
        self.assertEqual(len({task_id for _, task_id in results}), 1)
        self.assertEqual(CommunityTask.objects.filter(creator=self.member, idempotency_key=payload['idempotency_key']).count(), 1)


@override_settings(**TEST_SETTINGS)
class CommunityWebSocketAcceptanceTests(CommunityFixtures, TransactionTestCase):
    async def open_socket(self):
        _, token = await database_sync_to_async(AuthToken.objects.create)(self.member)
        communicator = WebsocketCommunicator(
            URLRouter(websocket_urlpatterns), f'/ws/chat/{self.conversation.pk}/?token={token}',
        )
        connected, _ = await communicator.connect()
        self.assertTrue(connected)
        initial = []
        for _ in range(10):
            event = await communicator.receive_json_from(timeout=3)
            initial.append(event)
            # connect() sends a snapshot and queues one group presence event.
            # Consume both before testing subsequent live-delivery behavior.
            if any(item['type'] == 'history' for item in initial) and sum(item['type'] == 'presence' for item in initial) >= 2:
                break
        self.assertTrue(any(event['type'] == 'history' for event in initial))
        return communicator

    def test_connected_socket_rechecks_removed_membership_before_delivery_and_send(self):
        message = self.message(text='Revoked live delivery')

        async def exercise():
            communicator = await self.open_socket()
            try:
                await database_sync_to_async(
                    CommunityMembership.objects.filter(group=self.group, user=self.member).update,
                )(state='removed')
                await get_channel_layer().group_send(f'chat_{self.conversation.pk}', {
                    'type': 'chat.message', 'message_id': message.pk,
                })
                if not await communicator.receive_nothing(timeout=0.15):
                    output = await communicator.receive_output(timeout=1)
                    self.assertEqual(output['type'], 'websocket.close', output)
                    self.assertEqual(output['code'], 4403)
                    return
                await communicator.send_json_to({'type': 'message', 'text': 'Must not persist'})
                event = await communicator.receive_output(timeout=1)
                self.assertEqual(event['type'], 'websocket.close')
                self.assertEqual(event['code'], 4403)
            finally:
                await communicator.disconnect()

        async_to_sync(exercise)()
        self.assertFalse(Message.objects.filter(text='Must not persist').exists())

    def test_socket_image_upload_cannot_bypass_image_permission_as_document(self):
        self.group.post_permissions.update(image=False, document=True)
        self.group.save()

        async def exercise():
            communicator = await self.open_socket()
            try:
                await communicator.send_json_to({
                    'type': 'file', 'filename': 'blocked.png', 'content_type': 'image/png',
                    'data': base64.b64encode(b'blocked-image').decode('ascii'),
                })
                result = await communicator.receive_json_from()
                self.assertEqual(result['type'], 'error', result)
            finally:
                await communicator.disconnect()

        async_to_sync(exercise)()
        self.assertFalse(Message.objects.filter(attachment_name='blocked.png').exists())
