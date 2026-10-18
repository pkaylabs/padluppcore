import tempfile
from datetime import timedelta
from unittest.mock import patch

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import override_settings
from django.utils import timezone
from rest_framework.test import APITestCase

from accounts.models import User
from .community_models import (
    CommunityCategory, CommunityGroup, CommunityTask, CommunityTaskMembership, CommunityTaskPeriod,
)
from .models import Conversation, ConversationMembership, Goal, GoalCheckin, GoalMembership, Notification


@override_settings(SECURE_SSL_REDIRECT=False, EMAIL_NOTIFICATIONS_ENABLED=False,
                   PASSWORD_HASHERS=['django.contrib.auth.hashers.MD5PasswordHasher'])
class CheckinPolicyTests(APITestCase):
    def setUp(self):
        self.media = tempfile.TemporaryDirectory()
        self.addCleanup(self.media.cleanup)
        setting = override_settings(PRIVATE_MEDIA_ROOT=self.media.name)
        setting.enable()
        self.addCleanup(setting.disable)
        self.owner = User.objects.create_user(email='check-owner@test.com', name='Owner', password='test-password')
        self.member = User.objects.create_user(email='check-member@test.com', name='Member', password='test-password')
        self.internal = User.objects.create_user(email='check-staff@test.com', name='Internal', password='test-password', is_staff=True)
        self.internal.is_staff = True
        self.internal.save(update_fields=['is_staff'])
        self.goal = Goal.objects.create(user=self.owner, title='Sprint', start_date=timezone.localdate(), target_date=timezone.localdate() + timedelta(days=10))
        group = CommunityGroup.objects.create(creator=self.owner, category=CommunityCategory.objects.create(name='Testing checkins'),
            conversation=Conversation.objects.create(is_group=True), name='Testing')
        self.task = CommunityTask.objects.create(group=group, goal=self.goal, creator=self.owner, idempotency_key='check-policy',
            invitation_deadline=timezone.now() + timedelta(days=2))
        self.conversation = Conversation.objects.create(goal=self.goal, is_group=True)
        for user in [self.owner, self.member]:
            membership = CommunityTaskMembership.objects.create(task=self.task, user=user, state='active', role='admin' if user == self.owner else 'member', joined_at=timezone.now())
            CommunityTaskPeriod.objects.create(membership=membership, joined_at=membership.joined_at)
            GoalMembership.objects.get_or_create(goal=self.goal, user=user)
            ConversationMembership.objects.get_or_create(conversation=self.conversation, user=user)
        self.client.force_authenticate(self.owner)

    def payload(self, evidence=True, **extra):
        payload = {'goal': self.goal.pk, 'scheduled_for': timezone.localdate().isoformat(), 'status': 'partial',
            'mood': 'motivated', 'completion_percent': 25, 'update_text': 'First section completed', 'blocker': '', 'next_focus': 'Second section'}
        if evidence:
            payload['evidence'] = SimpleUploadedFile('proof.png', b'image', content_type='image/png')
        payload.update(extra)
        return payload

    def schedule(self, user=None):
        return GoalCheckin.objects.get_or_create(goal=self.goal, user=user or self.owner, scheduled_for=timezone.localdate())[0]

    def test_system_cycle_and_evidence_are_required(self):
        response = self.client.post('/api-v1/checkins/', self.payload(), format='multipart')
        self.assertEqual(response.status_code, 400)
        self.schedule()
        response = self.client.post('/api-v1/checkins/', self.payload(evidence=False), format='multipart')
        self.assertEqual(response.status_code, 400)
        self.assertIn('evidence', response.data)

    def test_get_cycles_then_submit_and_review_other_member_only(self):
        rows = self.client.get('/api-v1/checkins/', {'goal': self.goal.pk})
        self.assertEqual(rows.status_code, 200, rows.data)
        self.assertTrue(GoalCheckin.objects.filter(goal=self.goal, user=self.owner, scheduled_for=timezone.localdate()).exists())
        submitted = self.client.post('/api-v1/checkins/', self.payload(), format='multipart')
        self.assertEqual(submitted.status_code, 200, submitted.data)
        self.assertEqual(submitted.data['mood'], 'motivated')
        self.assertEqual(submitted.data['next_focus'], 'Second section')
        self.assertEqual(submitted.data['review_status'], 'pending')
        url = f'/api-v1/checkins/{submitted.data["id"]}/review/'
        self.assertEqual(self.client.post(url, {'approved': True}, format='json').status_code, 403)
        self.client.force_authenticate(self.member)
        review = self.client.post(url, {'approved': False}, format='json')
        self.assertEqual(review.status_code, 200, review.data)
        self.assertEqual(review.data['review_status'], 'clarification')
        self.assertEqual(review.data['reviewer']['id'], self.member.pk)
        self.assertIsNotNone(review.data['reviewed_at'])

    def test_evidence_repeatable_after_archive_and_internal_deletion(self):
        self.schedule()
        submitted = self.client.post('/api-v1/checkins/', self.payload(evidence_view_once=True), format='multipart')
        self.assertEqual(submitted.status_code, 200, submitted.data)
        checkin = GoalCheckin.objects.get(pk=submitted.data['id'])
        self.assertFalse(checkin.evidence_view_once)
        self.assertIsNone(checkin.evidence_expires_at)
        self.task.status = 'archived'
        self.task.save()
        self.goal.is_active = False
        self.goal.save()
        self.client.force_authenticate(self.member)
        url = f'/api-v1/checkins/{checkin.pk}/evidence/'
        for _ in range(2):
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200)
            b''.join(response.streaming_content)
        self.assertEqual(self.client.post(f'/api-v1/checkins/{checkin.pk}/review/', {'approved': True}, format='json').status_code, 403)
        deletion = f'/api-v1/checkins/{checkin.pk}/delete-evidence/'
        self.assertEqual(self.client.post(deletion, {'reason': 'Sensitive'}, format='json').status_code, 403)
        self.client.force_authenticate(self.internal)
        self.assertEqual(self.client.post(deletion, {}, format='json').status_code, 400)
        name, storage = checkin.evidence.name, checkin.evidence.storage
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(deletion, {'reason': 'Sensitive evidence'}, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        self.assertFalse(storage.exists(name))
        self.assertEqual(self.client.get(url).status_code, 404)

    def test_removed_members_and_platform_banned_users_lose_evidence(self):
        checkin = self.schedule()
        checkin.evidence = SimpleUploadedFile('proof.png', b'image', content_type='image/png')
        checkin.save()
        self.client.force_authenticate(self.member)
        CommunityTaskMembership.objects.filter(task=self.task, user=self.member).update(state='removed')
        self.assertEqual(self.client.get(f'/api-v1/checkins/{checkin.pk}/evidence/').status_code, 404)
        self.owner.is_active = False
        self.owner.save()
        self.client.force_authenticate(self.owner)
        self.assertEqual(self.client.get(f'/api-v1/checkins/{checkin.pk}/evidence/').status_code, 404)

    def test_png_evidence_has_previewable_mime_and_private_response_headers(self):
        checkin = self.schedule()
        checkin.evidence = SimpleUploadedFile('proof.png', b'image', content_type='image/png')
        checkin.save()
        response = self.client.get(f'/api-v1/checkins/{checkin.pk}/evidence/')
        try:
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response['Content-Type'], 'image/png')
            self.assertTrue(response['Content-Disposition'].startswith('inline;'))
            self.assertEqual(response['X-Content-Type-Options'], 'nosniff')
            self.assertEqual(response['Cache-Control'], 'private, no-store, max-age=0')
            self.assertEqual(response['Content-Security-Policy'], "sandbox; default-src 'none'")
        finally:
            b''.join(response.streaming_content)

    def test_unsafe_and_unknown_evidence_is_download_only(self):
        checkin = self.schedule()
        for extension, supplied_mime in [('html', 'text/html'), ('svg', 'image/svg+xml'), ('bin', 'image/png')]:
            with self.subTest(extension=extension):
                checkin.evidence = SimpleUploadedFile(f'proof.{extension}', b'unsafe-content', content_type=supplied_mime)
                checkin.save()
                response = self.client.get(f'/api-v1/checkins/{checkin.pk}/evidence/')
                try:
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(response['Content-Type'], 'application/octet-stream')
                    self.assertTrue(response['Content-Disposition'].startswith('attachment;'))
                    self.assertEqual(response['X-Content-Type-Options'], 'nosniff')
                    self.assertEqual(response['Cache-Control'], 'private, no-store, max-age=0')
                finally:
                    b''.join(response.streaming_content)

    def test_no_cycle_reassignment_or_duplicate_submission(self):
        checkin = self.schedule()
        response = self.client.patch(f'/api-v1/checkins/{checkin.pk}/', self.payload(scheduled_for=(timezone.localdate() - timedelta(days=1)).isoformat()), format='multipart')
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.client.post('/api-v1/checkins/', self.payload(), format='multipart').status_code, 200)
        self.assertEqual(self.client.post('/api-v1/checkins/', self.payload(), format='multipart').status_code, 409)

    def test_legacy_personal_submission_keeps_compatibility(self):
        goal = Goal.objects.create(user=self.owner, title='Personal')
        response = self.client.post('/api-v1/checkins/', {'goal': goal.pk, 'scheduled_for': timezone.localdate().isoformat(),
            'status': 'partial', 'completion_percent': 0, 'update_text': 'No progress today'}, format='json')
        self.assertEqual(response.status_code, 201, response.data)

    def test_legacy_join_share_do_not_bypass_community_enrollment(self):
        self.goal.is_public = True
        self.goal.save()
        outsider = User.objects.create_user(email='check-outsider@test.com', name='Outsider', password='test-password')
        self.client.force_authenticate(outsider)
        response = self.client.post('/api-v1/goals/join-goal/', {'shared_id': str(self.goal.shared_id)}, format='json')
        self.assertEqual(response.status_code, 403)
        self.client.force_authenticate(self.owner)
        self.assertEqual(self.client.post(f'/api-v1/goals/{self.goal.pk}/share/', {'emails': [outsider.email]}, format='json').status_code, 403)

    def test_can_review_is_authoritative_for_pending_self_and_nonmember_admin(self):
        checkin = self.schedule()
        url = f'/api-v1/checkins/{checkin.pk}/'
        self.client.force_authenticate(self.member)
        self.assertFalse(self.client.get(url).data['can_review'])
        self.client.force_authenticate(self.owner)
        submitted = self.client.post('/api-v1/checkins/', self.payload(), format='multipart')
        self.assertEqual(submitted.status_code, 200, submitted.data)
        self.assertFalse(submitted.data['can_review'])
        self.client.force_authenticate(self.member)
        self.assertTrue(self.client.get(url).data['can_review'])
        self.assertTrue(self.client.post(url + 'review/', {'approved': True}, format='json').data['can_review'])
        self.client.force_authenticate(self.internal)
        self.assertFalse(self.client.get(url).data['can_review'])
        self.assertEqual(self.client.post(url + 'review/', {'approved': True}, format='json').status_code, 403)

    def test_can_review_is_false_for_readonly_lifecycle_and_departed_members(self):
        checkin = self.schedule()
        submitted = self.client.post('/api-v1/checkins/', self.payload(), format='multipart')
        self.assertEqual(submitted.status_code, 200, submitted.data)
        url = f'/api-v1/checkins/{checkin.pk}/'
        self.client.force_authenticate(self.member)
        for status in ['archived', 'frozen', 'completed', 'cancelled']:
            with self.subTest(status=status):
                self.task.status = status
                self.task.save(update_fields=['status'])
                self.assertFalse(self.client.get(url).data['can_review'])
                self.assertEqual(self.client.post(url + 'review/', {'approved': True}, format='json').status_code, 403)
        self.task.status = 'active'
        self.task.save(update_fields=['status'])
        membership = CommunityTaskMembership.objects.get(task=self.task, user=self.member)
        membership.state = 'left'
        membership.save(update_fields=['state'])
        membership.periods.update(ended_at=timezone.now())
        self.assertFalse(self.client.get(url).data['can_review'])
        self.assertEqual(self.client.post(url + 'review/', {'approved': True}, format='json').status_code, 403)
        membership.state = 'removed'
        membership.save(update_fields=['state'])
        self.assertEqual(self.client.get(url).status_code, 404)

    def test_evidence_download_metadata_is_safe_basename_and_readonly(self):
        checkin = self.schedule()
        submitted = self.client.post('/api-v1/checkins/', self.payload(
            evidence_name='../spoof.html', evidence_mime='text/html'), format='multipart')
        self.assertEqual(submitted.status_code, 200, submitted.data)
        self.assertTrue(submitted.data['evidence_name'].endswith('.png'))
        self.assertNotIn('/', submitted.data['evidence_name'])
        self.assertNotIn('\\', submitted.data['evidence_name'])
        self.assertEqual(submitted.data['evidence_mime'], 'image/png')
        for extension, mime in [('docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'),
                                ('svg', 'application/octet-stream'), ('bin', 'application/octet-stream')]:
            with self.subTest(extension=extension):
                checkin.evidence = SimpleUploadedFile(f'proof.{extension}', b'evidence')
                checkin.save()
                response = self.client.get(f'/api-v1/checkins/{checkin.pk}/')
                self.assertEqual(response.data['evidence_mime'], mime)
                self.assertTrue(response.data['evidence_name'].endswith('.' + extension))
                download = self.client.get(f'/api-v1/checkins/{checkin.pk}/evidence/')
                self.assertEqual(download['Content-Type'], mime)
                self.assertTrue(download['Content-Disposition'].startswith('attachment;'))
                b''.join(download.streaming_content)
        checkin.evidence = None
        checkin.save()
        response = self.client.get(f'/api-v1/checkins/{checkin.pk}/')
        self.assertIsNone(response.data['evidence_name'])
        self.assertIsNone(response.data['evidence_mime'])

    def test_admin_protected_files_render_readonly_without_url_or_delete_bypass(self):
        from django.contrib import admin
        from django.test import Client
        from .models import Message
        checkin = self.schedule()
        checkin.evidence = SimpleUploadedFile('private.png', b'evidence', content_type='image/png')
        checkin.save()
        message = Message.objects.create(conversation=self.conversation, sender=self.owner,
            attachment=SimpleUploadedFile('private.pdf', b'%PDF', content_type='application/pdf'))
        self.owner.is_staff = self.owner.is_superuser = True
        self.owner.save(update_fields=['is_staff', 'is_superuser'])
        client = Client()
        client.force_login(self.owner)
        for model, obj, file_field in [('goalcheckin', checkin, 'evidence'), ('message', message, 'attachment')]:
            with self.subTest(model=model):
                url = f'/admin/api/{model}/{obj.pk}/change/'
                response = client.get(url)
                self.assertEqual(response.status_code, 200)
                self.assertNotIn(f'name="{file_field}"', response.content.decode())
                self.assertEqual(client.post(url, {file_field + '-clear': 'on', '_save': 'Save'}).status_code, 403)
                self.assertEqual(client.post(f'/admin/api/{model}/{obj.pk}/delete/', {'post': 'yes'}).status_code, 403)
                obj.refresh_from_db()
                self.assertTrue(getattr(obj, file_field))
        self.assertNotIn(CommunityTask, admin.site._registry)

    def test_submission_notifies_only_enabled_active_peers_once(self):
        expected = {self.member.pk}
        for label, state, enabled, active, deleted in [
            ('peer', 'active', True, True, False), ('left', 'left', True, True, False),
            ('removed', 'removed', True, True, False), ('banned', 'banned', True, True, False),
            ('pending', 'pending', True, True, False), ('disabled', 'active', False, True, False),
            ('inactive', 'active', True, False, False), ('deleted', 'active', True, True, True),
        ]:
            user = User.objects.create_user(email=f'check-{label}@test.com', name=label, password='test-password')
            user.notify_on_reminders, user.is_active, user.deleted = enabled, active, deleted
            user.save(update_fields=['notify_on_reminders', 'is_active', 'deleted'])
            membership = CommunityTaskMembership.objects.create(task=self.task, user=user, state=state,
                joined_at=timezone.now() - timedelta(days=1))
            CommunityTaskPeriod.objects.create(membership=membership, joined_at=membership.joined_at)
            if label == 'peer':
                expected.add(user.pk)
        self.schedule()
        submitted = self.client.post('/api-v1/checkins/', self.payload(), format='multipart')
        self.assertEqual(submitted.status_code, 200, submitted.data)
        notifications = Notification.objects.filter(type='community_checkin_submitted')
        self.assertEqual(set(notifications.values_list('user_id', flat=True)), expected)
        self.assertEqual(notifications.count(), len(expected))
        self.assertFalse(Notification.objects.filter(type='new_message').exists())
        self.assertFalse(notifications.filter(user=self.owner).exists())
        self.client.force_authenticate(self.member)
        notice = notifications.get(user=self.member)
        response = self.client.get(f'/api-v1/notifications/{notice.pk}/')
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data['payload']['goal_id'], self.goal.pk)
        self.assertEqual(response.data['payload']['task_id'], self.task.pk)
        self.assertEqual(response.data['payload']['checkin_id'], submitted.data['id'])
        self.assertNotIn('update_text', response.data['payload'])
        self.assertNotIn('blocker', response.data['payload'])
        self.assertNotIn('evidence_url', response.data['payload'])
        self.client.force_authenticate(self.owner)
        self.assertEqual(self.client.post('/api-v1/checkins/', self.payload(), format='multipart').status_code, 409)
        self.assertEqual(notifications.count(), len(expected))
        self.assertEqual(self.client.patch(f'/api-v1/checkins/{submitted.data["id"]}/', self.payload(), format='multipart').status_code, 400)
        self.assertEqual(notifications.count(), len(expected))

    def test_review_notifies_only_active_submitter_without_self_or_duplicate_alert(self):
        self.schedule()
        submitted = self.client.post('/api-v1/checkins/', self.payload(), format='multipart')
        url = f'/api-v1/checkins/{submitted.data["id"]}/review/'
        self.assertEqual(self.client.post(url, {'approved': True}, format='json').status_code, 403)
        self.assertFalse(Notification.objects.filter(type='community_checkin_reviewed').exists())
        self.client.force_authenticate(self.member)
        response = self.client.post(url, {'approved': False}, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        notice = Notification.objects.get(type='community_checkin_reviewed')
        self.assertEqual(notice.user_id, self.owner.pk)
        self.assertEqual(notice.payload['review_status'], 'clarification')
        self.assertEqual(notice.payload['reviewer'], {'id': self.member.pk, 'name': self.member.name, 'avatar': None})
        self.assertEqual(self.client.post(url, {'approved': True}, format='json').status_code, 200)
        self.assertEqual(Notification.objects.filter(type='community_checkin_reviewed').count(), 2)
        self.assertEqual(self.client.post(url, {'approved': True}, format='json').status_code, 200)
        self.assertEqual(Notification.objects.filter(type='community_checkin_reviewed').count(), 2)
        self.assertFalse(Notification.objects.filter(type='community_checkin_reviewed', user=self.member).exists())
        Notification.objects.filter(type='community_checkin_reviewed').delete()
        CommunityTaskMembership.objects.filter(task=self.task, user=self.owner).update(state='left')
        self.assertEqual(self.client.post(url, {'approved': False}, format='json').status_code, 200)
        self.assertFalse(Notification.objects.filter(type='community_checkin_reviewed').exists())

    @override_settings(EMAIL_NOTIFICATIONS_ENABLED=True, MAILGUN_API_KEY='test', MAILGUN_DOMAIN='test', MAILGUN_FROM_EMAIL='test@example.com')
    @patch('api.signals.enqueue_notification_push')
    @patch('api.signals.send_mailgun_email')
    def test_checkin_notification_rechecks_departure_before_fetch_email_and_push(self, mail, push):
        self.schedule()
        with self.captureOnCommitCallbacks(execute=True):
            submitted = self.client.post('/api-v1/checkins/', self.payload(), format='multipart')
            self.assertEqual(submitted.status_code, 200, submitted.data)
            notice = Notification.objects.get(type='community_checkin_submitted', user=self.member)
            CommunityTaskMembership.objects.filter(task=self.task, user=self.member).update(state='left')
        self.assertNotIn(notice.pk, [call.args[0] for call in push.call_args_list])
        self.assertNotIn(self.member.email, [call.kwargs['to_email'] for call in mail.call_args_list])
        self.client.force_authenticate(self.member)
        for state in ['left', 'removed', 'banned']:
            with self.subTest(state=state):
                CommunityTaskMembership.objects.filter(task=self.task, user=self.member).update(state=state)
                self.assertEqual(self.client.get(f'/api-v1/notifications/{notice.pk}/').status_code, 404)
        from .push import send_notification_push
        # The synchronous worker call must not close the TestCase transaction.
        with patch('api.push._access_token') as token, patch('api.push.close_old_connections'):
            send_notification_push(notice.pk)
        token.assert_not_called()

    @override_settings(EMAIL_NOTIFICATIONS_ENABLED=True, MAILGUN_API_KEY='test', MAILGUN_DOMAIN='test', MAILGUN_FROM_EMAIL='test@example.com')
    @patch('api.signals.enqueue_notification_push')
    @patch('api.signals.send_mailgun_email')
    def test_checkin_notifications_honor_reminder_preferences_on_creation_and_delivery(self, mail, push):
        self.member.notify_on_reminders = False
        self.member.save(update_fields=['notify_on_reminders'])
        self.schedule()
        submitted = self.client.post('/api-v1/checkins/', self.payload(), format='multipart')
        self.assertEqual(submitted.status_code, 200, submitted.data)
        self.assertFalse(Notification.objects.filter(type='community_checkin_submitted').exists())
        self.member.notify_on_reminders = True
        self.member.save(update_fields=['notify_on_reminders'])
        with self.captureOnCommitCallbacks(execute=True):
            notice = Notification.objects.create(user=self.member, type='community_checkin_submitted', payload={
                'goal_id': self.goal.pk, 'task_id': self.task.pk, 'checkin_id': submitted.data['id'],
            })
            self.member.notify_on_reminders = False
            self.member.save(update_fields=['notify_on_reminders'])
        self.assertNotIn(notice.pk, [call.args[0] for call in push.call_args_list])
        self.assertNotIn(self.member.email, [call.kwargs['to_email'] for call in mail.call_args_list])
        self.client.force_authenticate(self.member)
        # Existing in-app history remains available; the opt-out stops delivery.
        self.assertEqual(self.client.get(f'/api-v1/notifications/{notice.pk}/').status_code, 200)
