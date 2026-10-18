import tempfile
from datetime import timedelta
from unittest.mock import patch

from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.exceptions import ValidationError as DjangoValidationError
from django.test import override_settings
from django.utils import timezone
from rest_framework.test import APITestCase

from accounts.models import User
from .community_models import CommunityCategory, CommunityGroup, CommunityMembership, CommunityMembershipPeriod, CommunityReport, CommunityTask, CommunityTaskMembership, CommunityTaskPeriod
from .community_messaging import cleanup_retained_attachments, delete_selection, set_report_review, visible_messages
from .message_models import MessageHidden, MessagePin, MessagePoll, MessagePollOption, MessagePollVote, RetainedMessageAttachment, RetainedMessageEvidence
from .models import ContentReport, Conversation, ConversationMembership, Goal, GoalMembership, Message, Notification
from .serializers import MessageSerializer


@override_settings(SECURE_SSL_REDIRECT=False, EMAIL_NOTIFICATIONS_ENABLED=False,
                   PASSWORD_HASHERS=['django.contrib.auth.hashers.MD5PasswordHasher'])
class CommunityMessagingPolicyTests(APITestCase):
    def setUp(self):
        self.media = tempfile.TemporaryDirectory()
        self.addCleanup(self.media.cleanup)
        settings = override_settings(PRIVATE_MEDIA_ROOT=self.media.name)
        settings.enable()
        self.addCleanup(settings.disable)
        self.owner = User.objects.create_user(email='chat-owner@test.com', name='Owner', password='test-password')
        self.member = User.objects.create_user(email='chat-member@test.com', name='Member', password='test-password')
        self.other = User.objects.create_user(email='chat-other@test.com', name='Other', password='test-password')
        self.conversation = Conversation.objects.create(is_group=True, name='Study session')
        self.group = CommunityGroup.objects.create(
            creator=self.owner, category=CommunityCategory.objects.create(name='Testing messaging'),
            conversation=self.conversation, name='Study session',
        )
        self.admit(self.owner, 'admin')
        self.membership = self.admit(self.member)
        self.client.force_authenticate(self.member)

    def admit(self, user, role='member'):
        membership = CommunityMembership.objects.create(group=self.group, user=user, state='active', role=role, joined_at=timezone.now())
        CommunityMembershipPeriod.objects.create(membership=membership, joined_at=membership.joined_at)
        ConversationMembership.objects.create(conversation=self.conversation, user=user)
        return membership

    def message(self, sender=None, text='Hello', age=None, attachment=False):
        message = Message.objects.create(conversation=self.conversation, sender=sender or self.member, text=text,
            attachment=SimpleUploadedFile('proof.pdf', b'%PDF-test', content_type='application/pdf') if attachment else None,
            attachment_name='proof.pdf' if attachment else '', attachment_mime='application/pdf' if attachment else '')
        if age:
            Message.objects.filter(pk=message.pk).update(created_at=timezone.now() - age)
            message.refresh_from_db()
        return message

    def test_delete_for_me_hides_only_requester_and_legacy_preview(self):
        message = self.message(self.owner, age=timedelta(days=2))
        response = self.client.post('/api-v1/community/messages/delete-selection/', {'ids': [message.pk], 'scope': 'me'}, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        self.assertTrue(MessageHidden.objects.filter(message=message, user=self.member).exists())
        self.assertFalse(visible_messages(Message.objects.filter(pk=message.pk), self.member).exists())
        self.assertTrue(visible_messages(Message.objects.filter(pk=message.pk), self.owner).exists())
        self.assertEqual(self.client.get(f'/api-v1/messages/{message.pk}/').status_code, 404)
        preview = self.client.get(f'/api-v1/conversations/{self.conversation.pk}/')
        self.assertIsNone(preview.data['last_message'])

    def test_mixed_ineligible_bulk_selection_is_atomic(self):
        recent = self.message()
        old = self.message(age=timedelta(minutes=16))
        response = self.client.post('/api-v1/community/messages/delete-selection/', {'ids': [recent.pk, old.pk], 'scope': 'everyone'}, format='json')
        self.assertEqual(response.status_code, 403)
        self.assertFalse(Message.objects.filter(pk__in=[recent.pk, old.pk], recalled_at__isnull=False).exists())

    def test_sender_deletion_placeholder_revokes_all_attachment_surfaces(self):
        message = self.message(attachment=True)
        MessagePin.objects.create(message=message, pinned_by=self.member)
        storage, name = message.attachment.storage, message.attachment.name
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post('/api-v1/community/messages/delete-selection/', {'ids': [message.pk], 'scope': 'everyone'}, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        self.assertFalse(storage.exists(name))
        self.assertFalse(MessagePin.objects.filter(message=message).exists())
        data = self.client.get(f'/api-v1/messages/{message.pk}/').data
        self.assertEqual(data['text'], 'This message was deleted')
        self.assertEqual(data['deletion_kind'], 'sender')
        self.assertIsNone(data['attachment'])
        self.assertEqual(self.client.get(f'/api-v1/community/messages/{message.pk}/attachment/').status_code, 404)

    def test_moderation_requires_reason_and_audits_actor(self):
        message = self.message(age=timedelta(days=3))
        self.client.force_authenticate(self.owner)
        url = '/api-v1/community/messages/delete-selection/'
        self.assertEqual(self.client.post(url, {'ids': [message.pk], 'scope': 'everyone'}, format='json').status_code, 400)
        response = self.client.post(url, {'ids': [message.pk], 'scope': 'everyone', 'reason': 'Harassment'}, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        message.refresh_from_db()
        self.assertEqual(message.deleted_by, self.owner)
        self.assertEqual(message.deletion_reason, 'Harassment')
        self.assertEqual(self.group.audit.get(action='message_removed').actor, self.owner)
        self.assertEqual(self.client.get(f'/api-v1/messages/{message.pk}/').data['text'], 'This message was removed by a moderator')

    def test_report_hold_is_internal_only_then_purged_on_resolution(self):
        message = self.message(attachment=True)
        report = ContentReport.objects.create(message=message, reporter=self.owner, reported_user=self.member, reason='spam')
        with self.captureOnCommitCallbacks(execute=True):
            delete_selection(self.member, [message.pk], 'everyone')
        hold = RetainedMessageAttachment.objects.get(message=message)
        name, storage = hold.file.name, hold.file.storage
        self.assertTrue(storage.exists(name))
        self.assertEqual(self.client.get(f'/api-v1/community/messages/{message.pk}/retained-attachment/').status_code, 403)
        self.owner.is_staff = True
        self.owner.save(update_fields=['is_staff'])
        self.client.force_authenticate(self.owner)
        response = self.client.get(f'/api-v1/community/messages/{message.pk}/retained-attachment/')
        self.assertEqual(response.status_code, 200)
        response.close()
        report.status = 'dismissed'
        report.save()
        with self.captureOnCommitCallbacks(execute=True):
            cleanup_retained_attachments()
        self.assertFalse(storage.exists(name))

    def test_old_resources_do_not_leak_chat_body_or_reply(self):
        old = self.message(self.owner, text='Private pre-window text', age=timedelta(days=40), attachment=True)
        self.assertFalse(visible_messages(Message.objects.filter(pk=old.pk), self.member).exists())
        self.assertTrue(visible_messages(Message.objects.filter(pk=old.pk), self.member, resources=True).exists())
        request = type('Request', (), {'user': self.member, 'build_absolute_uri': lambda _, value: value})()
        data = MessageSerializer(old, context={'request': request, 'resources': True}).data
        self.assertEqual(data['text'], '')
        self.assertIsNone(data['reply_to'])
        response = self.client.get(f'/api-v1/community/messages/{old.pk}/attachment/')
        self.assertEqual(response.status_code, 200)
        response.close()
        self.membership.state = 'removed'
        self.membership.save()
        self.assertEqual(self.client.get(f'/api-v1/community/messages/{old.pk}/attachment/').status_code, 404)

    def test_poll_votes_and_post_permission(self):
        response = self.client.post('/api-v1/community/messages/', {
            'conversation': self.conversation.pk, 'poll': {'question': 'When?', 'options': ['Today', 'Tomorrow'], 'multiple_answers': False},
        }, format='json')
        self.assertEqual(response.status_code, 201, response.data)
        message_id, options = response.data['id'], response.data['poll']['options']
        vote_url = f'/api-v1/community/messages/{message_id}/vote/'
        self.assertEqual(self.client.post(vote_url, {'option_ids': [o['id'] for o in options]}, format='json').status_code, 400)
        voted = self.client.post(vote_url, {'option_ids': [options[0]['id']]}, format='json')
        self.assertEqual(voted.data['poll']['options'][0]['votes'][0]['id'], self.member.pk)
        self.group.post_permissions['poll'] = False
        self.group.save()
        denied = self.client.post('/api-v1/community/messages/', {'conversation': self.conversation.pk,
            'poll': {'question': 'When?', 'options': ['Today', 'Tomorrow']}}, format='json')
        self.assertEqual(denied.status_code, 403)

    def test_replies_and_legacy_post_obey_access(self):
        message = self.message(self.owner, age=timedelta(days=40))
        response = self.client.post('/api-v1/messages/', {'conversation': self.conversation.pk, 'text': 'Reply', 'reply_to_message_id': message.pk}, format='json')
        self.assertEqual(response.status_code, 400)
        self.membership.state = 'left'
        self.membership.save()
        self.membership.periods.update(ended_at=timezone.now())
        denied = self.client.post('/api-v1/messages/', {'conversation': self.conversation.pk, 'text': 'No posting'}, format='json')
        self.assertEqual(denied.status_code, 403)

    def test_sender_can_remove_task_post_without_touching_underlying_task(self):
        message = Message.objects.create(conversation=self.conversation, sender=self.member, kind=Message.KIND_GOAL,
            text='A task card', metadata={'event': 'community_task_created', 'community_task_id': 123})
        response = self.client.post('/api-v1/community/messages/delete-selection/', {'ids': [message.pk], 'scope': 'everyone'}, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        message.refresh_from_db()
        self.assertEqual(message.deletion_kind, 'sender')

    def test_legacy_direct_chats_keep_deletion_and_private_uploads(self):
        conversation = Conversation.objects.create()
        ConversationMembership.objects.create(conversation=conversation, user=self.member)
        ConversationMembership.objects.create(conversation=conversation, user=self.other)
        response = self.client.post('/api-v1/messages/', {'conversation': conversation.pk,
            'attachment': SimpleUploadedFile('note.txt', b'hello', content_type='text/plain')}, format='multipart')
        self.assertEqual(response.status_code, 201, response.data)
        self.assertIn('/community/messages/', response.data['attachment'])
        recalled = self.client.post(f'/api-v1/messages/{response.data["id"]}/recall/')
        self.assertEqual(recalled.status_code, 200, recalled.data)
        self.assertEqual(recalled.data['text'], 'This message was deleted')

    def test_old_link_resources_return_only_urls_not_prejoin_body(self):
        message = self.message(self.owner, text='Do not disclose this old body https://example.com/guide', age=timedelta(days=40))
        response = self.client.get(f'/api-v1/conversations/{self.conversation.pk}/resources/', {'type': 'links'})
        self.assertEqual(response.status_code, 200, response.data)
        self.assertIn('results', response.data)
        resource = next(row for row in response.data['results'] if row['id'] == message.pk)
        self.assertEqual(resource['links'], ['https://example.com/guide'])
        self.assertEqual(resource['text'], '')
        self.assertIsNone(resource['reply_to'])

    def test_internal_moderation_of_reported_private_message_does_not_grant_chat_access(self):
        conversation = Conversation.objects.create()
        ConversationMembership.objects.create(conversation=conversation, user=self.member)
        ConversationMembership.objects.create(conversation=conversation, user=self.other)
        message = Message.objects.create(conversation=conversation, sender=self.other, text='Reported private content',
            attachment=SimpleUploadedFile('report.pdf', b'%PDF', content_type='application/pdf'), attachment_name='report.pdf')
        ContentReport.objects.create(message=message, conversation=conversation, reporter=self.member, reported_user=self.other, reason='harassment')
        self.owner.is_staff = True
        self.owner.save(update_fields=['is_staff'])
        self.client.force_authenticate(self.owner)
        self.assertEqual(self.client.get(f'/api-v1/messages/{message.pk}/').status_code, 404)
        self.assertEqual(self.client.get(f'/api-v1/conversations/{conversation.pk}/').status_code, 404)
        evidence_url = f'/api-v1/community/messages/{message.pk}/report-evidence/'
        evidence = self.client.get(evidence_url)
        self.assertEqual(evidence.status_code, 200, evidence.data)
        self.assertEqual(evidence.data['text'], 'Reported private content')
        self.assertIsNone(evidence.data['reply_to'])
        attachment = self.client.get(evidence_url, {'file': '1'})
        self.assertEqual(attachment.status_code, 200)
        attachment.close()
        url = '/api-v1/community/messages/delete-selection/'
        self.assertEqual(self.client.post(url, {'ids': [message.pk], 'scope': 'everyone'}, format='json').status_code, 400)
        response = self.client.post(url, {'ids': [message.pk], 'scope': 'everyone', 'reason': 'Reported harassment'}, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        message.refresh_from_db()
        self.assertEqual(message.deletion_kind, 'moderator')
        self.assertEqual(self.client.get(f'/api-v1/messages/{message.pk}/').status_code, 404)

    def notification(self, message, user=None, **payload):
        return Notification.objects.create(user=user or self.member, type='new_message', payload={
            'conversation_id': message.conversation_id, 'message_id': message.pk,
            'sender_name': message.sender.name, 'preview': message.text, **payload,
        })

    def test_notification_sender_deletion_and_hidden_messages_follow_current_access(self):
        message = self.message(self.owner, text='Delete this sensitive preview')
        notification = self.notification(message, attachment='old-private-url', reply_to={'text': 'Old reply body'})
        delete_selection(self.owner, [message.pk], 'everyone')
        response = self.client.get(f'/api-v1/notifications/{notification.pk}/')
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data['payload']['preview'], 'This message was deleted')
        self.assertNotIn('Delete this sensitive preview', str(response.data))
        self.assertNotIn('old-private-url', str(response.data))
        self.assertNotIn('Old reply body', str(response.data))
        delete_selection(self.member, [message.pk], 'me')
        self.assertEqual(self.client.get(f'/api-v1/notifications/{notification.pk}/').status_code, 404)

    def test_notification_delete_for_me_is_scoped_and_old_reply_snapshot_is_absent(self):
        self.admit(self.other)
        parent = self.message(self.owner, text='Old inaccessible parent', age=timedelta(days=40))
        reply = self.message(self.owner, text='Visible reply')
        reply.reply_to_message = parent
        reply.save()
        mine = self.notification(reply, reply_to={'text': parent.text}, attachment='unprotected-snapshot-url')
        theirs = self.notification(reply, user=self.other)
        response = self.client.get(f'/api-v1/notifications/{mine.pk}/')
        self.assertNotIn(parent.text, str(response.data))
        self.assertNotIn('unprotected-snapshot-url', str(response.data))
        delete_selection(self.member, [reply.pk], 'me')
        self.assertEqual(self.client.get(f'/api-v1/notifications/{mine.pk}/').status_code, 404)
        self.client.force_authenticate(self.other)
        self.assertEqual(self.client.get(f'/api-v1/notifications/{theirs.pk}/').data['payload']['preview'], 'Visible reply')

    def test_notification_history_ends_at_voluntary_exit(self):
        message = self.message(self.owner, text='Before departure')
        prior = self.notification(message)
        response = self.client.post(f'/api-v1/community/groups/{self.group.pk}/leave/', {'reason': 'goals_achieved'}, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        after = self.notification(message, preview='A new event referring to an old message')
        self.assertEqual(self.client.get(f'/api-v1/notifications/{prior.pk}/').status_code, 200)
        self.assertEqual(self.client.get(f'/api-v1/notifications/{after.pk}/').status_code, 404)

    def test_notification_absence_gap_stays_hidden_after_rejoin(self):
        now = timezone.now()
        self.membership.periods.update(joined_at=now - timedelta(days=7), ended_at=now - timedelta(days=4))
        CommunityMembershipPeriod.objects.create(membership=self.membership, joined_at=now - timedelta(days=1))
        message = self.message(self.owner, text='Pre-exit message', age=timedelta(days=5))
        notification = self.notification(message)
        Notification.objects.filter(pk=notification.pk).update(created_at=now - timedelta(days=3))
        self.assertEqual(self.client.get(f'/api-v1/notifications/{notification.pk}/').status_code, 404)

    def test_source_group_removal_keeps_independent_pod_notifications(self):
        goal = Goal.objects.create(user=self.owner, title='Independent pod')
        task = CommunityTask.objects.create(group=self.group, goal=goal, creator=self.owner,
            idempotency_key='notification-pod', invitation_deadline=timezone.now() + timedelta(days=1))
        conversation = Conversation.objects.create(goal=goal, is_group=True)
        for user in [self.owner, self.member]:
            member = CommunityTaskMembership.objects.create(task=task, user=user, state='active', joined_at=timezone.now())
            CommunityTaskPeriod.objects.create(membership=member, joined_at=member.joined_at)
            GoalMembership.objects.get_or_create(goal=goal, user=user)
            ConversationMembership.objects.get_or_create(conversation=conversation, user=user)
        message = Message.objects.create(conversation=conversation, sender=self.owner, text='Pod content is independent')
        notification = self.notification(message)
        self.membership.state = 'removed'
        self.membership.save()
        response = self.client.get(f'/api-v1/notifications/{notification.pk}/')
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data['payload']['preview'], message.text)

    def test_task_creation_alert_is_available_to_source_members_without_pod_access(self):
        goal = Goal.objects.create(user=self.owner, title='A new group task')
        task = CommunityTask.objects.create(group=self.group, goal=goal, creator=self.owner,
            idempotency_key='task-creation-alert', invitation_deadline=timezone.now() + timedelta(days=1))
        notification = Notification.objects.create(user=self.member, type='community_task_created', payload={
            'group_id': self.group.pk, 'task_id': task.pk, 'goal_id': goal.pk, 'title': goal.title,
        })
        response = self.client.get(f'/api-v1/notifications/{notification.pk}/')
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data['payload']['title'], goal.title)
        self.assertEqual(self.client.get(f'/api-v1/goals/{goal.pk}/').status_code, 404)

    @override_settings(EMAIL_NOTIFICATIONS_ENABLED=True, MAILGUN_API_KEY='test', MAILGUN_DOMAIN='test', MAILGUN_FROM_EMAIL='test@example.com')
    @patch('api.signals.enqueue_notification_push')
    @patch('api.signals.send_mailgun_email')
    def test_muted_chat_suppresses_app_email_push_but_keeps_removal_notice(self, mail, push):
        self.membership.notifications_muted = True
        self.membership.save()
        message = self.message(self.owner, text='Muted preview')
        with self.captureOnCommitCallbacks(execute=True):
            notification = self.notification(message)
        mail.assert_not_called()
        push.assert_not_called()
        self.assertEqual(self.client.get(f'/api-v1/notifications/{notification.pk}/').status_code, 404)
        with self.captureOnCommitCallbacks(execute=True):
            notice = Notification.objects.create(user=self.member, type='community_membership_changed', payload={
                'group_id': self.group.pk, 'action': 'remove', 'reason': 'Rule violation',
                'message': 'Do not expose this snapshot', 'preview': 'Muted preview',
            })
        response = self.client.get(f'/api-v1/notifications/{notice.pk}/')
        self.assertEqual(response.status_code, 200, response.data)
        self.assertIn('Rule violation', str(response.data))
        self.assertNotIn('Muted preview', str(response.data))
        self.assertNotIn('Do not expose this snapshot', str(response.data))
        mail.assert_called_once()
        push.assert_called_once()

    @override_settings(EMAIL_NOTIFICATIONS_ENABLED=True, MAILGUN_API_KEY='test', MAILGUN_DOMAIN='test', MAILGUN_FROM_EMAIL='test@example.com')
    @patch('api.signals.enqueue_notification_push')
    @patch('api.signals.send_mailgun_email')
    def test_pending_delivery_rechecks_revocation_and_push_worker_does_too(self, mail, push):
        message = self.message(self.owner, text='Revoke before delivery')
        with self.captureOnCommitCallbacks(execute=True):
            notification = self.notification(message)
            self.membership.state = 'removed'
            self.membership.save()
        mail.assert_not_called()
        push.assert_not_called()
        from .push import send_notification_push
        with patch('api.push._access_token') as access_token:
            send_notification_push(notification.pk)
        access_token.assert_not_called()

    def pod_for_internal_access(self):
        goal = Goal.objects.create(user=self.owner, title='Internal review pod')
        CommunityTask.objects.create(group=self.group, goal=goal, creator=self.owner,
            idempotency_key='internal-access', invitation_deadline=timezone.now() + timedelta(days=1))
        conversation = Conversation.objects.create(goal=goal, is_group=True)
        Message.objects.create(conversation=conversation, sender=self.owner,
            text='Pod reference https://example.com/pod-guide')
        return goal, conversation

    def assert_internal_legacy_access(self, flag):
        goal, pod = self.pod_for_internal_access()
        private_goal = Goal.objects.create(user=self.owner, title='Private legacy goal')
        private_pod = Conversation.objects.create(goal=private_goal, is_group=True)
        private_chat = Conversation.objects.create()
        ConversationMembership.objects.create(conversation=private_chat, user=self.owner)
        self.assertFalse(GoalMembership.objects.filter(goal=goal, user=self.other).exists())
        self.assertFalse(ConversationMembership.objects.filter(conversation=pod, user=self.other).exists())
        setattr(self.other, flag, True)
        self.other.save(update_fields=[flag])
        self.client.force_authenticate(self.other)
        goals = self.client.get('/api-v1/goals/')
        self.assertEqual(goals.status_code, 200, goals.data)
        self.assertIn(goal.pk, {row['id'] for row in goals.data['results']})
        self.assertNotIn(private_goal.pk, {row['id'] for row in goals.data['results']})
        conversations = self.client.get('/api-v1/conversations/')
        self.assertEqual(conversations.status_code, 200, conversations.data)
        ids = {row['id'] for row in conversations.data['results']}
        self.assertTrue({self.conversation.pk, pod.pk}.issubset(ids))
        self.assertTrue({private_chat.pk, private_pod.pk}.isdisjoint(ids))
        for path in [f'goals/{goal.pk}/', f'goals/{goal.pk}/members/',
                     f'conversations/{self.conversation.pk}/', f'conversations/{pod.pk}/',
                     f'conversations/{pod.pk}/media/', f'conversations/{pod.pk}/resources/?type=links']:
            url = '/api-v1/' + path
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200, (url, response.data))
        for path in [f'goals/{private_goal.pk}/', f'conversations/{private_chat.pk}/', f'conversations/{private_pod.pk}/']:
            self.assertEqual(self.client.get('/api-v1/' + path).status_code, 404, path)

    def test_staff_nonmember_has_only_internal_community_legacy_access(self):
        self.assert_internal_legacy_access('is_staff')

    def test_superuser_nonmember_has_only_internal_community_legacy_access(self):
        self.assert_internal_legacy_access('is_superuser')

    def test_founder_nonmember_has_only_internal_community_legacy_access(self):
        self.assert_internal_legacy_access('is_founder')

    def test_normal_nonmembers_and_source_members_cannot_read_private_pods(self):
        goal, pod = self.pod_for_internal_access()
        for user in [self.other, self.member]:
            with self.subTest(user=user.pk):
                self.client.force_authenticate(user)
                goals = self.client.get('/api-v1/goals/')
                self.assertNotIn(goal.pk, {row['id'] for row in goals.data['results']})
                conversations = self.client.get('/api-v1/conversations/')
                self.assertNotIn(pod.pk, {row['id'] for row in conversations.data['results']})
                for path in [f'goals/{goal.pk}/', f'goals/{goal.pk}/members/',
                             f'conversations/{pod.pk}/', f'conversations/{pod.pk}/media/',
                             f'conversations/{pod.pk}/resources/?type=links']:
                    self.assertEqual(self.client.get('/api-v1/' + path).status_code, 404, path)
        self.client.force_authenticate(self.other)
        self.assertEqual(self.client.get(f'/api-v1/conversations/{self.conversation.pk}/').status_code, 404)

    def test_revoking_internal_privilege_immediately_removes_legacy_reads(self):
        goal, pod = self.pod_for_internal_access()
        self.other.is_founder = True
        self.other.save(update_fields=['is_founder'])
        self.client.force_authenticate(self.other)
        self.assertEqual(self.client.get(f'/api-v1/goals/{goal.pk}/').status_code, 200)
        self.assertEqual(self.client.get(f'/api-v1/conversations/{pod.pk}/').status_code, 200)
        self.other.is_founder = False
        self.other.save(update_fields=['is_founder'])
        self.client.force_authenticate(self.other)
        self.assertEqual(self.client.get(f'/api-v1/goals/{goal.pk}/').status_code, 404)
        self.assertEqual(self.client.get(f'/api-v1/conversations/{pod.pk}/').status_code, 404)
        self.assertEqual(self.client.get('/api-v1/goals/').data['results'], [])
        self.assertEqual(self.client.get('/api-v1/conversations/').data['results'], [])

    def test_reported_text_survives_sender_deletion_only_as_private_immutable_evidence(self):
        parent = self.message(self.owner, text='Unreported private reply context')
        message = self.message(text='Reported original text')
        message.reply_to_message = parent
        message.is_a_reply = True
        message.save()
        report = ContentReport.objects.create(message=message, conversation=self.conversation,
            reporter=self.owner, reported_user=self.member, reason='harassment', details='Report details to retain')
        delete_selection(self.member, [message.pk], 'everyone')
        hold = RetainedMessageEvidence.objects.get(message=message)
        self.assertEqual(hold.snapshot['message']['text'], 'Reported original text')
        self.assertEqual(hold.snapshot['reports'][0]['id'], report.pk)
        self.assertEqual(hold.snapshot['reports'][0]['details'], 'Report details to retain')
        self.assertEqual(self.client.get(f'/api-v1/messages/{message.pk}/').data['text'], 'This message was deleted')
        url = f'/api-v1/community/messages/{message.pk}/report-evidence/'
        self.assertEqual(self.client.get(url).status_code, 403)
        self.client.force_authenticate(self.owner)
        self.assertEqual(self.client.get(url).status_code, 403)
        self.owner.is_staff = True
        self.owner.save(update_fields=['is_staff'])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data['text'], 'Reported original text')
        self.assertTrue(response.data['is_retained_evidence'])
        self.assertIsNotNone(response.data['evidence_captured_at'])
        self.assertIsNone(response.data['reply_to'])
        self.assertNotIn(parent.text, str(response.data))
        self.assertIn('no-store', response['Cache-Control'])
        hold.snapshot['message']['text'] = 'Changed snapshot'
        with self.assertRaises(DjangoValidationError):
            hold.save()
        hold.refresh_from_db()
        self.assertEqual(hold.snapshot['message']['text'], 'Reported original text')
        from django.db.models.deletion import ProtectedError
        with self.assertRaises(ProtectedError):
            message.delete()

    def test_reported_old_poll_survives_moderation_with_named_votes(self):
        message = self.message(text='Choose the next session', age=timedelta(days=40))
        poll = MessagePoll.objects.create(message=message, question='When?', multiple_answers=False)
        today = MessagePollOption.objects.create(poll=poll, text='Today', position=0)
        MessagePollOption.objects.create(poll=poll, text='Tomorrow', position=1)
        MessagePollVote.objects.create(option=today, user=self.member)
        report = CommunityReport.objects.create(message=message, group=self.group, reporter=self.member,
            reported_user=self.member, reason='Inappropriate poll', details='Community-only report')
        self.client.force_authenticate(self.owner)
        response = self.client.post('/api-v1/community/messages/delete-selection/', {
            'ids': [message.pk], 'scope': 'everyone', 'reason': 'Inappropriate poll',
        }, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        self.assertFalse(MessagePoll.objects.filter(message=message).exists())
        self.assertEqual(self.client.get(f'/api-v1/messages/{message.pk}/').status_code, 404)
        snapshot = RetainedMessageEvidence.objects.get(message=message).snapshot
        self.assertEqual(snapshot['reports'][0]['id'], report.pk)
        self.assertEqual(snapshot['message']['poll']['question'], 'When?')
        self.assertEqual(snapshot['message']['poll']['options'][0]['votes'][0]['id'], self.member.pk)
        self.owner.is_staff = True
        self.owner.save(update_fields=['is_staff'])
        evidence = self.client.get(f'/api-v1/community/messages/{message.pk}/report-evidence/')
        self.assertEqual(evidence.data['text'], 'Choose the next session')
        self.assertEqual(evidence.data['poll']['options'][0]['text'], 'Today')

    def test_admin_can_remove_unreported_old_resource_without_expanding_chat_reads(self):
        message = self.message(self.member, age=timedelta(days=40), attachment=True)
        storage, name = message.attachment.storage, message.attachment.name
        self.client.force_authenticate(self.owner)
        self.assertEqual(self.client.get(f'/api-v1/messages/{message.pk}/').status_code, 404)
        resources = self.client.get(f'/api-v1/conversations/{self.conversation.pk}/resources/?type=files')
        item = next(row for row in resources.data['results'] if row['id'] == message.pk)
        self.assertTrue(item['can_moderate'])
        self.assertEqual(item['text'], '')
        url = '/api-v1/community/messages/delete-selection/'
        self.assertEqual(self.client.post(url, {'ids': [message.pk], 'scope': 'everyone'}, format='json').status_code, 400)
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(url, {
                'ids': [message.pk], 'scope': 'everyone', 'reason': 'Old inappropriate resource',
            }, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        self.assertFalse(storage.exists(name))
        self.assertFalse(RetainedMessageEvidence.objects.filter(message=message).exists())
        self.assertTrue(self.group.audit.filter(action='message_removed', actor=self.owner, target_id=str(message.pk)).exists())

    def test_snapshot_and_file_are_purged_only_after_all_reports_final(self):
        message = self.message(attachment=True)
        reports = [ContentReport.objects.create(message=message, conversation=self.conversation,
            reporter=user, reported_user=self.member, reason='spam') for user in [self.owner, self.other]]
        for report in reports:
            CommunityReport.objects.create(content_report=report, message=message, group=self.group,
                reporter=report.reporter, reason=report.reason)
        delete_selection(self.member, [message.pk], 'everyone')
        hold = RetainedMessageAttachment.objects.get(message=message)
        storage, name = hold.file.storage, hold.file.name
        self.owner.is_staff = True
        self.owner.save(update_fields=['is_staff'])
        with self.captureOnCommitCallbacks(execute=True):
            set_report_review(reports[0], self.owner, 'dismissed', 'First review complete')
        self.assertTrue(RetainedMessageEvidence.objects.filter(message=message).exists())
        self.assertTrue(storage.exists(name))
        with self.captureOnCommitCallbacks(execute=True):
            set_report_review(reports[1].community_report, self.owner, 'actioned', 'Final review complete')
        self.assertFalse(RetainedMessageEvidence.objects.filter(message=message).exists())
        self.assertFalse(RetainedMessageAttachment.objects.filter(message=message).exists())
        self.assertFalse(storage.exists(name))
        reports[1].refresh_from_db()
        self.assertEqual(reports[1].status, 'actioned')
        self.client.force_authenticate(self.owner)
        self.assertEqual(self.client.get(f'/api-v1/community/messages/{message.pk}/report-evidence/').status_code, 404)
        self.assertTrue(self.group.audit.filter(action='message_deleted', actor=self.member).exists())
        self.assertTrue(self.group.audit.filter(action='report.actioned', actor=self.owner, reason='Final review complete').exists())

    def test_django_admin_resolution_syncs_mirror_and_purges_private_holds(self):
        from django.test import Client
        message = self.message(attachment=True)
        report = ContentReport.objects.create(message=message, conversation=self.conversation,
            reporter=self.owner, reported_user=self.member, reason='spam')
        mirror = CommunityReport.objects.create(content_report=report, message=message, group=self.group,
            reporter=self.owner, reason=report.reason)
        delete_selection(self.member, [message.pk], 'everyone')
        held_file = RetainedMessageAttachment.objects.get(message=message)
        storage, name = held_file.file.storage, held_file.file.name
        self.owner.is_staff = self.owner.is_superuser = True
        self.owner.save(update_fields=['is_staff', 'is_superuser'])
        client = Client()
        client.force_login(self.owner)
        with self.captureOnCommitCallbacks(execute=True):
            response = client.post(f'/admin/api/contentreport/{report.pk}/change/', {
                'status': 'dismissed', 'moderator_notes': 'Admin review complete', '_save': 'Save',
            })
        self.assertEqual(response.status_code, 302)
        report.refresh_from_db()
        mirror.refresh_from_db()
        self.assertEqual((report.status, mirror.status), ('dismissed', 'dismissed'))
        self.assertEqual(mirror.reviewer, self.owner)
        self.assertEqual(mirror.notes, 'Admin review complete')
        self.assertIsNotNone(mirror.reviewed_at)
        self.assertFalse(RetainedMessageEvidence.objects.filter(message=message).exists())
        self.assertFalse(RetainedMessageAttachment.objects.filter(message=message).exists())
        self.assertFalse(storage.exists(name))

    def test_active_content_mime_is_downgraded_on_normal_and_report_downloads(self):
        self.owner.is_staff = True
        self.owner.save(update_fields=['is_staff'])
        for filename, mime in [('proof.svg', 'image/svg+xml'), ('proof.html', 'text/html'),
                               ('spoof.svg', 'image/png'), ('unknown.bin', 'application/x-unknown')]:
            with self.subTest(filename=filename):
                message = Message.objects.create(conversation=self.conversation, sender=self.member,
                    attachment=SimpleUploadedFile(filename, b'<script>unsafe</script>', content_type=mime),
                    attachment_name=filename, attachment_mime=mime)
                response = self.client.get(f'/api-v1/community/messages/{message.pk}/attachment/')
                self.assertEqual(response['Content-Type'], 'application/octet-stream')
                self.assertTrue(response['Content-Disposition'].startswith('attachment;'))
                response.close()
                data = self.client.get(f'/api-v1/messages/{message.pk}/').data
                self.assertEqual(data['attachment_mime'], 'application/octet-stream')
                ContentReport.objects.create(message=message, reporter=self.owner, reason='spam')
                delete_selection(self.member, [message.pk], 'everyone')
                self.client.force_authenticate(self.owner)
                response = self.client.get(f'/api-v1/community/messages/{message.pk}/report-evidence/?file=1')
                self.assertEqual(response['Content-Type'], 'application/octet-stream')
                self.assertTrue(response['Content-Disposition'].startswith('attachment;'))
                response.close()
    def test_socket_conversation_list_matches_internal_community_scope(self):
        from .consumers import ConversationsConsumer, _ScopeRequest
        goal, pod = self.pod_for_internal_access()
        private_chat = Conversation.objects.create()
        ConversationMembership.objects.create(conversation=private_chat, user=self.owner)
        self.other.is_staff = True
        self.other.save(update_fields=['is_staff'])
        consumer = ConversationsConsumer()
        consumer.serializer_request = _ScopeRequest({'user': self.other})
        conversation_payload = ConversationsConsumer.__dict__['get_user_conversations_payload'].func
        rows = conversation_payload(consumer, self.other.pk)
        self.assertEqual({row['id'] for row in rows}, {self.conversation.pk, pod.pk})
        self.other.is_staff = False
        self.other.save(update_fields=['is_staff'])
        self.assertEqual(conversation_payload(consumer, self.other.pk), [])

    @override_settings(EMAIL_NOTIFICATIONS_ENABLED=True, MAILGUN_API_KEY='test', MAILGUN_DOMAIN='test', MAILGUN_FROM_EMAIL='test@example.com')
    @patch('api.signals.enqueue_notification_push')
    @patch('api.signals.send_mailgun_email')
    def test_pending_group_and_pod_invitation_notifications_survive_no_content_access(self, mail, push):
        from .community_access import can_access_goal, can_read_group
        from .community_messaging import notification_payload
        from .community_services import invite_task_users, manage_group_member
        goal, pod = self.pod_for_internal_access()
        task = goal.community_task
        CommunityTaskMembership.objects.create(task=task, user=self.owner, state='active', role='admin')
        with self.captureOnCommitCallbacks(execute=True):
            group_invite = manage_group_member(self.group, self.owner, self.other, 'invite')
            pod_invite = invite_task_users(task, self.owner, [self.other.pk])[0]
        self.assertEqual(mail.call_count, 2)
        self.assertEqual(push.call_count, 2)
        self.assertFalse(can_read_group(self.group, self.other))
        self.assertFalse(can_access_goal(goal, self.other))
        self.client.force_authenticate(self.other)
        for event, invitation in [('community_invitation', group_invite), ('community_task_invitation', pod_invite)]:
            with self.subTest(event=event):
                notification = Notification.objects.get(user=self.other, type=event)
                response = self.client.get(f'/api-v1/notifications/{notification.pk}/')
                self.assertEqual(response.status_code, 200, response.data)
                self.assertEqual(response.data['payload']['invitation_id'], invitation.pk)
                self.assertIsNotNone(notification_payload(notification, self.other, delivery=True))
                self.assertNotIn('preview', response.data['payload'])
                self.assertNotIn('conversation_id', response.data['payload'])
        listing = self.client.get('/api-v1/notifications/')
        self.assertEqual({row['type'] for row in listing.data['results']}, {'community_invitation', 'community_task_invitation'})
        for conversation in [self.conversation, pod]:
            self.assertEqual(self.client.get(f'/api-v1/conversations/{conversation.pk}/').status_code, 404)
        self.assertEqual(self.client.get(f'/api-v1/goals/{goal.pk}/').status_code, 404)
        self.client.force_authenticate(self.member)
        notice = Notification.objects.get(user=self.other, type='community_task_invitation')
        self.assertEqual(self.client.get(f'/api-v1/notifications/{notice.pk}/').status_code, 404)

    @override_settings(EMAIL_NOTIFICATIONS_ENABLED=True, MAILGUN_API_KEY='test', MAILGUN_DOMAIN='test', MAILGUN_FROM_EMAIL='test@example.com')
    @patch('api.signals.enqueue_notification_push')
    @patch('api.signals.send_mailgun_email')
    def test_pending_invitee_receives_safe_deadline_alert_without_pod_access(self, mail, push):
        from .community_access import can_access_goal
        from .community_messaging import notification_payload
        from .community_services import generate_task_cycles
        goal, pod = self.pod_for_internal_access()
        task = goal.community_task
        task.invitation_deadline = timezone.now() - timedelta(minutes=1)
        task.save(update_fields=['invitation_deadline'])
        task.invitations.create(user=self.other, invited_by=self.owner)
        CommunityTaskMembership.objects.create(task=task, user=self.owner, state='active', role='admin')
        with self.captureOnCommitCallbacks(execute=True):
            generate_task_cycles(task)
        notice = Notification.objects.get(user=self.other, type='community_invitation_closed')
        self.assertIn(notice.pk, [call.args[0] for call in push.call_args_list])
        self.assertIn(self.other.email, [call.kwargs['to_email'] for call in mail.call_args_list])
        self.assertFalse(can_access_goal(goal, self.other))
        notice.payload.update(preview='Restricted preview', reply_to={'text': 'Private reply'},
                              attachment='private-storage-url', conversation_id=pod.pk)
        notice.save(update_fields=['payload'])
        self.client.force_authenticate(self.other)
        response = self.client.get(f'/api-v1/notifications/{notice.pk}/')
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data['payload'], {
            'task_id': task.pk, 'message': 'The task invitation deadline has passed.',
        })
        self.assertEqual(notification_payload(notice, self.other, delivery=True), response.data['payload'])
        listing = self.client.get('/api-v1/notifications/')
        self.assertIn(notice.pk, {row['id'] for row in listing.data['results']})
        self.assertEqual(self.client.get(f'/api-v1/goals/{goal.pk}/').status_code, 404)
        self.assertEqual(self.client.get(f'/api-v1/conversations/{pod.pk}/').status_code, 404)

    def test_pod_admin_can_remove_own_old_message_with_reason_and_scoped_audit(self):
        goal, pod = self.pod_for_internal_access()
        membership = CommunityTaskMembership.objects.create(task=goal.community_task, user=self.member,
            state='active', role='admin', joined_at=timezone.now())
        CommunityTaskPeriod.objects.create(membership=membership, joined_at=membership.joined_at)
        message = Message.objects.create(conversation=pod, sender=self.owner, text='Old inappropriate pod message',
            attachment=SimpleUploadedFile('pod.pdf', b'%PDF', content_type='application/pdf'), attachment_name='pod.pdf', attachment_mime='application/pdf')
        Message.objects.filter(pk=message.pk).update(created_at=timezone.now() - timedelta(days=40))
        storage, name = message.attachment.storage, message.attachment.name
        self.client.force_authenticate(self.member)
        resources = self.client.get(f'/api-v1/conversations/{pod.pk}/resources/?type=files')
        item = next(row for row in resources.data['results'] if row['id'] == message.pk)
        self.assertTrue(item['can_moderate'])
        self.assertTrue(item['can_delete_everyone'])
        url = '/api-v1/community/messages/delete-selection/'
        self.assertEqual(self.client.post(url, {'ids': [message.pk], 'scope': 'everyone'}, format='json').status_code, 400)
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(url, {'ids': [message.pk], 'scope': 'everyone', 'reason': 'Pod misconduct'}, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        self.assertFalse(storage.exists(name))
        message.refresh_from_db()
        self.assertEqual(message.deletion_kind, 'moderator')
        self.assertEqual(message.deleted_by, self.member)
        from .community_models import CommunityAudit
        record = CommunityAudit.objects.get(action='message_removed', target_id=str(message.pk))
        self.assertEqual(record.actor, self.member)
        self.assertEqual(record.reason, 'Pod misconduct')
        self.assertEqual(record.outcome['goal_id'], goal.pk)
        self.assertEqual(record.outcome['community_task_id'], goal.community_task.pk)
        self.assertIsNone(record.group_id)

    def test_pod_moderation_denies_cross_pods_source_admin_and_stale_membership(self):
        first_goal, first_pod = self.pod_for_internal_access()
        second_goal = Goal.objects.create(user=self.owner, title='Second independent pod')
        second_task = CommunityTask.objects.create(group=self.group, goal=second_goal, creator=self.owner,
            idempotency_key='second-moderation-pod', invitation_deadline=timezone.now() + timedelta(days=1))
        second_pod = Conversation.objects.create(goal=second_goal, is_group=True)
        for task, user in [(first_goal.community_task, self.member), (second_task, self.other)]:
            membership = CommunityTaskMembership.objects.create(task=task, user=user,
                state='active', role='admin', joined_at=timezone.now() - timedelta(days=1))
            CommunityTaskPeriod.objects.create(membership=membership, joined_at=membership.joined_at)
        first_message = Message.objects.create(conversation=first_pod, sender=self.owner, text='First pod content')
        second_message = Message.objects.create(conversation=second_pod, sender=self.owner, text='Second pod content')
        url = '/api-v1/community/messages/delete-selection/'
        for actor, message in [(self.member, second_message), (self.other, first_message), (self.owner, first_message)]:
            with self.subTest(actor=actor.pk, target=message.pk):
                self.client.force_authenticate(actor)
                response = self.client.post(url, {'ids': [message.pk], 'scope': 'everyone', 'reason': 'Wrong scope'}, format='json')
                self.assertEqual(response.status_code, 403, response.data)
        GoalMembership.objects.get_or_create(goal=first_goal, user=self.member, defaults={'role': 'admin'})
        ConversationMembership.objects.get_or_create(conversation=first_pod, user=self.member)
        membership = CommunityTaskMembership.objects.get(task=first_goal.community_task, user=self.member)
        self.client.force_authenticate(self.member)
        for state in ['left', 'removed', 'banned']:
            with self.subTest(state=state):
                membership.state = state
                membership.save(update_fields=['state'])
                self.assertEqual(self.client.post(url, {
                    'ids': [first_message.pk], 'scope': 'everyone', 'reason': 'Stale membership',
                }, format='json').status_code, 403)
        self.assertFalse(Message.objects.filter(pk__in=[first_message.pk, second_message.pk], recalled_at__isnull=False).exists())

    def test_internal_pod_moderation_does_not_grant_legacy_goal_or_dm_moderation(self):
        goal, pod = self.pod_for_internal_access()
        self.other.is_staff = True
        self.other.save(update_fields=['is_staff'])
        self.client.force_authenticate(self.other)
        message = Message.objects.create(conversation=pod, sender=self.owner, text='Internal pod moderation target')
        Message.objects.filter(pk=message.pk).update(created_at=timezone.now() - timedelta(days=40))
        url = '/api-v1/community/messages/delete-selection/'
        response = self.client.post(url, {'ids': [message.pk], 'scope': 'everyone', 'reason': 'Internal moderation'}, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        legacy_goal = Goal.objects.create(user=self.other, title='Legacy goal without community task')
        legacy = Conversation.objects.create(goal=legacy_goal, is_group=True)
        direct = Conversation.objects.create()
        ConversationMembership.objects.create(conversation=direct, user=self.other)
        for conversation in [legacy, direct]:
            with self.subTest(conversation=conversation.pk):
                target = Message.objects.create(conversation=conversation, sender=self.owner, text='Not a community pod')
                response = self.client.get(f'/api-v1/messages/{target.pk}/')
                self.assertFalse(response.data['can_moderate'])
                self.assertEqual(self.client.post(url, {
                    'ids': [target.pk], 'scope': 'everyone', 'reason': 'Not authorized',
                }, format='json').status_code, 403)

    def test_message_notifications_include_only_authorized_navigation_ids(self):
        message = self.message(self.owner)
        notice = self.notification(message, group_id=999, goal_id=999)
        data = self.client.get(f'/api-v1/notifications/{notice.pk}/').data['payload']
        self.assertEqual(data['group_id'], self.group.pk)
        self.assertNotIn('goal_id', data)
        goal, pod = self.pod_for_internal_access()
        membership = CommunityTaskMembership.objects.create(task=goal.community_task, user=self.member,
            state='active', joined_at=timezone.now() - timedelta(days=1))
        CommunityTaskPeriod.objects.create(membership=membership, joined_at=membership.joined_at)
        message = Message.objects.create(conversation=pod, sender=self.owner, text='Authorized pod notification')
        notice = self.notification(message, group_id=self.group.pk, goal_id=999)
        data = self.client.get(f'/api-v1/notifications/{notice.pk}/').data['payload']
        self.assertEqual(data['goal_id'], goal.pk)
        self.assertNotIn('group_id', data)
        membership.state = 'removed'
        membership.save(update_fields=['state'])
        self.assertEqual(self.client.get(f'/api-v1/notifications/{notice.pk}/').status_code, 404)

    def test_link_only_permission_allows_urls_but_not_captions_or_plain_text(self):
        self.group.post_permissions = dict.fromkeys(self.group.post_permissions, False)
        self.group.post_permissions['link'] = True
        self.group.save(update_fields=['post_permissions'])
        for prefix in ['/api-v1/messages/', '/api-v1/community/messages/']:
            with self.subTest(prefix=prefix):
                response = self.client.post(prefix, {
                    'conversation': self.conversation.pk, 'text': 'https://example.com/guide',
                }, format='json')
                self.assertEqual(response.status_code, 201, response.data)
                for text in ['Plain text is not allowed', 'Caption https://example.com/guide']:
                    response = self.client.post(prefix, {
                        'conversation': self.conversation.pk, 'text': text,
                    }, format='json')
                    self.assertEqual(response.status_code, 403, response.data)

    def test_pods_scope_filters_before_pagination_without_changing_ordinary_goals(self):
        pods = Goal.objects.bulk_create([
            Goal(user=self.member, title=f'Legacy pod {index}', is_shared=True) for index in range(24)
        ])
        personal = Goal.objects.bulk_create([
            Goal(user=self.member, title=f'Personal goal {index}') for index in range(25)
        ])
        ordinary = self.client.get('/api-v1/goals/')
        self.assertEqual(ordinary.data['count'], 49)
        self.assertEqual(len(ordinary.data['results']), 20)
        self.assertTrue({row['id'] for row in ordinary.data['results']}.issubset({goal.pk for goal in personal}))
        first = self.client.get('/api-v1/goals/', {'scope': 'pods'})
        self.assertEqual(first.status_code, 200, first.data)
        self.assertEqual(first.data['count'], 24)
        self.assertEqual(len(first.data['results']), 20)
        self.assertIn('scope=pods', first.data['next'])
        second = self.client.get('/api-v1/goals/', {'scope': 'pods', 'page': 2})
        self.assertEqual(second.status_code, 200, second.data)
        self.assertEqual(second.data['count'], 24)
        self.assertEqual(len(second.data['results']), 4)
        self.assertIsNone(second.data['next'])
        self.assertIn('scope=pods', second.data['previous'])
        ids = [row['id'] for row in first.data['results'] + second.data['results']]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(set(ids), {goal.pk for goal in pods})
        self.assertEqual(self.client.get('/api-v1/goals/', {'scope': 'other'}).data['count'], 49)

    def test_pods_scope_includes_legacy_kinds_but_never_revives_removed_pod_access(self):
        from .models import Partnership
        shared = Goal.objects.create(user=self.member, title='Shared flag', is_shared=True)
        multi = Goal.objects.bulk_create([Goal(user=self.owner, title='Legacy multi-member')])[0]
        GoalMembership.objects.bulk_create([
            GoalMembership(goal=multi, user=self.owner), GoalMembership(goal=multi, user=self.member),
        ])
        partnership = Partnership.objects.create(user_a=self.member, user_b=self.other)
        partnered = Goal.objects.bulk_create([Goal(user=self.owner, partnership=partnership, title='Legacy partnership')])[0]
        community = Goal.objects.create(user=self.owner, title='Community pod')
        task = CommunityTask.objects.create(group=self.group, goal=community, creator=self.owner,
            idempotency_key='pods-scope-active', invitation_deadline=timezone.now() + timedelta(days=1))
        CommunityTaskMembership.objects.create(task=task, user=self.member, state='active')
        removed = Goal.objects.create(user=self.owner, title='Removed community pod')
        removed_task = CommunityTask.objects.create(group=self.group, goal=removed, creator=self.owner,
            idempotency_key='pods-scope-removed', invitation_deadline=timezone.now() + timedelta(days=1))
        CommunityTaskMembership.objects.create(task=removed_task, user=self.member, state='removed')
        GoalMembership.objects.get_or_create(goal=removed, user=self.member)
        personal = Goal.objects.create(user=self.member, title='Personal only')
        response = self.client.get('/api-v1/goals/', {'scope': 'pods'})
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data['count'], 4)
        self.assertEqual({row['id'] for row in response.data['results']}, {shared.pk, multi.pk, partnered.pk, community.pk})
        self.assertEqual(self.client.get(f'/api-v1/goals/{removed.pk}/').status_code, 404)
        ordinary = self.client.get('/api-v1/goals/')
        self.assertEqual(ordinary.data['count'], 5)
        self.assertIn(personal.pk, {row['id'] for row in ordinary.data['results']})
        # Scope is a list-read concern, never a different write permission.
        response = self.client.patch(f'/api-v1/goals/{personal.pk}/?scope=pods', {'title': 'Still personal'}, format='json')
        self.assertEqual(response.status_code, 200, response.data)
