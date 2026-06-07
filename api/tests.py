from django.urls import reverse
from unittest.mock import patch
import base64
import tempfile

from django.conf import settings
from django.test import override_settings
from django.test import TransactionTestCase
from django.core.cache import cache
from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework.test import APIRequestFactory
from knox.models import AuthToken
from django.utils import timezone
from datetime import datetime, timezone as dt_timezone, timedelta

from accounts.models import User
from api.models import BuddyRequest, Partnership, Profile, Conversation, Message, Goal, GoalMembership, Task, TimerSession, Evidence, Notification, UserDailyActivity, InactivityNudgeLog, CheckinReminderLog, Waitlister
from api.serializers import UserSerializer, MessageSerializer
from api.consumers import _ScopeRequest
from django.core.files.uploadedfile import SimpleUploadedFile
from padluppcore.utils.email import EmailSendError
from asgiref.sync import async_to_sync
from api.consumers import ChatConsumer


@override_settings(EMAIL_NOTIFICATIONS_ENABLED=False)
class BuddyEndpointsTests(APITestCase):
	def _mk_user(self, *, email: str, phone: str, name: str, password: str = 'pass1234'):
		user = User(email=email, phone=phone, name=name)
		user.set_password(password)
		user.save()
		return user

	def setUp(self):
		self.user = self._mk_user(email='me@test.com', name='Me', phone='+10000000001')
		self.other = self._mk_user(email='other@test.com', name='Other', phone='+10000000002')
		self.pending_target = self._mk_user(email='pending@test.com', name='Pending', phone='+10000000003')
		self.not_similar = self._mk_user(email='nosim@test.com', name='NoSim', phone='+10000000004')

		Profile.objects.get_or_create(user=self.user, defaults={'experience': 'python django backend'})
		Profile.objects.get_or_create(user=self.other, defaults={'experience': 'django rest framework'})
		Profile.objects.get_or_create(user=self.pending_target, defaults={'experience': 'totally different topic'})
		Profile.objects.get_or_create(user=self.not_similar, defaults={'experience': 'unrelated cooking'})

		self.client.force_authenticate(user=self.user)

	@patch('api.viewsets.send_mailgun_email')
	def test_connect_and_invitations_accept_flow_creates_partnership(self, mock_send_mailgun_email):
		connect_url = reverse('buddies-connect')
		resp = self.client.post(connect_url, data={'to_user': self.other.id, 'message': 'Hey, want to connect?'}, format='json')
		self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
		self.assertEqual(resp.data['status'], BuddyRequest.STATUS_PENDING)
		self.assertEqual(resp.data['message'], 'Hey, want to connect?')
		mock_send_mailgun_email.assert_called()

		# Recipient sees it in invitations
		self.client.force_authenticate(user=self.other)
		inv_url = reverse('buddies-invitations')
		inv = self.client.get(inv_url)
		self.assertEqual(inv.status_code, status.HTTP_200_OK)
		self.assertEqual(len(inv.data), 1)
		self.assertEqual(inv.data[0]['message'], 'Hey, want to connect?')
		request_id = inv.data[0]['id']

		# Accept creates partnership
		accept_url = reverse('buddies-accept', kwargs={'pk': request_id})
		accepted = self.client.post(accept_url)
		self.assertEqual(accepted.status_code, status.HTTP_200_OK)
		partnership_id = accepted.data.get('partnership_id')
		self.assertIsNotNone(partnership_id)
		self.assertTrue(Notification.objects.filter(user=self.user, type='buddy_request_accepted').exists())

		# Partnership exists
		user_a, user_b = sorted([self.user, self.other], key=lambda u: u.id)
		self.assertTrue(Partnership.objects.filter(user_a=user_a, user_b=user_b).exists())

	@patch('api.viewsets.send_mailgun_email')
	def test_connect_sends_connection_request_email(self, mock_send_mailgun_email):
		connect_url = reverse('buddies-connect')
		resp = self.client.post(connect_url, data={'to_user': self.other.id, 'message': 'Yo'}, format='json')
		self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
		mock_send_mailgun_email.assert_called()
		called_kwargs = mock_send_mailgun_email.call_args.kwargs
		self.assertEqual(called_kwargs.get('to_email'), self.other.email)
		self.assertIn('https://app.padlupp.com', called_kwargs.get('text', ''))

	def test_reject_removes_from_invitations(self):
		BuddyRequest.objects.create(from_user=self.user, to_user=self.other)

		self.client.force_authenticate(user=self.other)
		inv_url = reverse('buddies-invitations')
		inv = self.client.get(inv_url)
		self.assertEqual(inv.status_code, status.HTTP_200_OK)
		self.assertEqual(len(inv.data), 1)
		request_id = inv.data[0]['id']

		reject_url = reverse('buddies-reject', kwargs={'pk': request_id})
		rejected = self.client.post(reject_url)
		self.assertEqual(rejected.status_code, status.HTTP_200_OK)

		inv2 = self.client.get(inv_url)
		self.assertEqual(inv2.status_code, status.HTTP_200_OK)
		self.assertEqual(len(inv2.data), 0)

	def test_finder_excludes_existing_connections_and_marks_pending(self):
		# Create an existing connection (partnership) between self.user and self.other
		user_a, user_b = sorted([self.user, self.other], key=lambda u: u.id)
		Partnership.objects.create(user_a=user_a, user_b=user_b)

		# Create a pending outgoing request to pending_target
		BuddyRequest.objects.create(from_user=self.user, to_user=self.pending_target, status=BuddyRequest.STATUS_PENDING)

		finder_url = reverse('buddies-finder')
		resp = self.client.get(finder_url)
		self.assertEqual(resp.status_code, status.HTTP_200_OK)
		returned_user_ids = {row['user']['id'] for row in resp.data}

		# Existing buddy should be excluded
		self.assertNotIn(self.other.id, returned_user_ids)
		# Pending request profile should be included even if not similar
		self.assertIn(self.pending_target.id, returned_user_ids)
		pending_row = next(r for r in resp.data if r['user']['id'] == self.pending_target.id)
		self.assertEqual(pending_row['connection_status'], 'pending')
		self.assertIsNotNone(pending_row['buddy_request_id'])
		# Unrelated and not pending should not appear
		self.assertNotIn(self.not_similar.id, returned_user_ids)

	def test_connections_returns_buddy_profiles(self):
		user_a, user_b = sorted([self.user, self.other], key=lambda u: u.id)
		Partnership.objects.create(user_a=user_a, user_b=user_b)

		connections_url = reverse('buddies-connections')
		resp = self.client.get(connections_url)
		self.assertEqual(resp.status_code, status.HTTP_200_OK)
		returned_user_ids = {row['user']['id'] for row in resp.data}
		self.assertEqual(returned_user_ids, {self.other.id})

	def test_userprofile_returns_profile(self):
		url = reverse('auth-userprofile')
		resp = self.client.get(url)
		self.assertEqual(resp.status_code, status.HTTP_200_OK)
		# Endpoint returns ProfileSerializer payload
		self.assertIn('user', resp.data)
		self.assertEqual(resp.data['user']['id'], self.user.id)

	def test_update_experience_updates_fields(self):
		url = reverse('onboarding-update-experience')
		resp = self.client.patch(url, data={'experience': 'new exp', 'interests': ['python', 'django']}, format='json')
		self.assertEqual(resp.status_code, status.HTTP_200_OK)
		self.assertEqual(resp.data['experience'], 'new exp')
		self.assertEqual(resp.data['interests'], ['python', 'django'])

	def test_update_user_patch(self):
		url = reverse('auth-user')
		resp = self.client.patch(
			url,
			data={
				'name': 'New Name',
				'preferred_notification_email': 'notify@test.com',
				'preferred_notification_phone': '+15550001111',
			},
			format='json',
		)
		self.assertEqual(resp.status_code, status.HTTP_200_OK)
		self.assertEqual(resp.data['name'], 'New Name')
		self.assertEqual(resp.data['preferred_notification_email'], 'notify@test.com')
		self.assertEqual(resp.data['preferred_notification_phone'], '+15550001111')

	@patch('api.viewsets.send_mailgun_email')
	def test_invite_adds_waitlist_and_sends_email(self, mock_send_mailgun_email):
		invite_url = reverse('auth-invite')
		resp = self.client.post(invite_url, data={'email': 'newperson@test.com', 'name': 'New Person'}, format='json')
		self.assertEqual(resp.status_code, status.HTTP_200_OK)
		self.assertEqual(resp.data.get('detail'), 'Invite sent.')
		self.assertTrue(resp.data.get('waitlisted'))

		self.assertTrue(Waitlister.objects.filter(email='newperson@test.com').exists())
		mock_send_mailgun_email.assert_called()
		called_kwargs = mock_send_mailgun_email.call_args.kwargs
		self.assertEqual(called_kwargs.get('to_email'), 'newperson@test.com')
		self.assertIn('Padlupp', called_kwargs.get('subject', ''))
		self.assertIn('https://app.padlupp.com', called_kwargs.get('text', ''))

	@patch('api.viewsets.send_mailgun_email')
	def test_invite_existing_user_rejected(self, mock_send_mailgun_email):
		# self.other exists from setUp
		invite_url = reverse('auth-invite')
		resp = self.client.post(invite_url, data={'email': self.other.email}, format='json')
		self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
		mock_send_mailgun_email.assert_not_called()

	def test_update_user_duplicate_phone_rejected(self):
		# Other user owns this phone
		other = User(email='dup@test.com', phone='+19998887777', name='Dup')
		other.set_password('pass1234')
		other.save()

		url = reverse('auth-user')
		resp = self.client.patch(url, data={'phone': '+19998887777'}, format='json')
		self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)


@override_settings(BETA_WAITLIST_ONLY=False)
class AuthLastLoginTests(APITestCase):
	def test_login_updates_last_login(self):
		user = User(email='lastlogin@test.com', phone='+10000000021', name='LL')
		user.set_password('pass1234')
		user.save()

		self.assertIsNone(user.last_login)
		url = reverse('auth-login')
		fixed_now = datetime(2026, 1, 3, 15, 0, 0, tzinfo=dt_timezone.utc)

		with patch('django.utils.timezone.now', return_value=fixed_now):
			resp = self.client.post(url, data={'email': 'lastlogin@test.com', 'password': 'pass1234'}, format='json')

		self.assertEqual(resp.status_code, status.HTTP_200_OK)
		user.refresh_from_db()
		self.assertEqual(user.last_login, fixed_now)
		self.assertTrue(UserDailyActivity.objects.filter(user=user, activity_date=fixed_now.date()).exists())


class StatsEndpointsTests(APITestCase):
	def _mk_user(self, *, email: str, phone: str, name: str, password: str = 'pass1234'):
		user = User(email=email, phone=phone, name=name)
		user.set_password(password)
		user.save()
		return user

	def setUp(self):
		self.user = self._mk_user(email='stats@test.com', name='Stats', phone='+10000000011')
		Profile.objects.get_or_create(user=self.user, defaults={'time_zone': 'UTC'})
		self.client.force_authenticate(user=self.user)

	def test_longest_streak_counts_last_login(self):
		url = reverse('stats-longest-streak')
		fixed_now = datetime(2026, 1, 3, 15, 0, 0, tzinfo=dt_timezone.utc)

		with patch('django.utils.timezone.now', return_value=fixed_now):
			# No activity and no last_login -> all zeros.
			self.user.last_login = None
			self.user.save(update_fields=['last_login'])
			self.client.force_authenticate(user=self.user)
			resp0 = self.client.get(url)
			self.assertEqual(resp0.status_code, status.HTTP_200_OK)
			self.assertEqual(resp0.data.get('longest_streak_count'), 0)
			self.assertEqual(resp0.data.get('current_streak_count'), 0)

			# last_login yesterday -> longest=1, current=0 (since 'today' not active).
			yesterday = fixed_now - timedelta(days=1)
			self.user.last_login = yesterday
			self.user.save(update_fields=['last_login'])
			self.client.force_authenticate(user=self.user)
			resp1 = self.client.get(url)
			self.assertEqual(resp1.status_code, status.HTTP_200_OK)
			self.assertEqual(resp1.data.get('longest_streak_count'), 1)
			self.assertEqual(resp1.data.get('current_streak_count'), 0)

			# last_login today -> longest=1, current=1.
			self.user.last_login = fixed_now
			self.user.save(update_fields=['last_login'])
			self.client.force_authenticate(user=self.user)
			resp2 = self.client.get(url)
			self.assertEqual(resp2.status_code, status.HTTP_200_OK)
			self.assertEqual(resp2.data.get('longest_streak_count'), 1)
			self.assertEqual(resp2.data.get('current_streak_count'), 1)

	def test_longest_streak_counts_login_days_from_tokens(self):
		url = reverse('stats-longest-streak')
		day1 = datetime(2026, 1, 2, 15, 0, 0, tzinfo=dt_timezone.utc)
		day2 = datetime(2026, 1, 3, 15, 0, 0, tzinfo=dt_timezone.utc)

		with patch('django.utils.timezone.now', return_value=day1):
			AuthToken.objects.create(self.user)

		with patch('django.utils.timezone.now', return_value=day2):
			AuthToken.objects.create(self.user)
			self.user.last_login = day2
			self.user.save(update_fields=['last_login'])
			self.client.force_authenticate(user=self.user)
			resp = self.client.get(url)

		self.assertEqual(resp.status_code, status.HTTP_200_OK)
		self.assertEqual(resp.data.get('longest_streak_count'), 2)
		self.assertEqual(resp.data.get('current_streak_count'), 2)

	def test_longest_streak_uses_daily_activity_source_of_truth(self):
		url = reverse('stats-longest-streak')
		day1 = datetime(2026, 1, 2, 10, 0, 0, tzinfo=dt_timezone.utc)
		day2 = datetime(2026, 1, 3, 11, 0, 0, tzinfo=dt_timezone.utc)

		UserDailyActivity.objects.create(
			user=self.user,
			activity_date=day1.date(),
			first_activity_at=day1,
			last_activity_at=day1,
			source='manual_seed',
		)
		UserDailyActivity.objects.create(
			user=self.user,
			activity_date=day2.date(),
			first_activity_at=day2,
			last_activity_at=day2,
			source='manual_seed',
		)

		with patch('django.utils.timezone.now', return_value=day2):
			resp = self.client.get(url)

		self.assertEqual(resp.status_code, status.HTTP_200_OK)
		self.assertEqual(resp.data.get('longest_streak_count'), 2)
		self.assertEqual(resp.data.get('current_streak_count'), 2)

	def test_longest_streak_any_activity(self):
		# Create activity on three consecutive days (UTC): 2026-01-01, 2026-01-02, 2026-01-03
		d1 = datetime(2026, 1, 1, 10, 0, 0, tzinfo=dt_timezone.utc)
		d2 = datetime(2026, 1, 2, 11, 0, 0, tzinfo=dt_timezone.utc)
		d3 = datetime(2026, 1, 3, 12, 0, 0, tzinfo=dt_timezone.utc)

		TimerSession.objects.create(user=self.user, started_at=d1, ended_at=d1)

		goal = Goal.objects.create(user=self.user, title='g', description='')
		task = Task.objects.create(goal=goal, owner=self.user, title='t', description='', status=Task.STATUS_COMPLETED)
		# Force updated_at to a deterministic value (auto_now would override on save)
		Task.objects.filter(id=task.id).update(updated_at=d3)

		evidence = Evidence.objects.create(submitted_by=self.user, task=task, text='x')
		Evidence.objects.filter(id=evidence.id).update(submitted_at=d2)


class InactivityNudgeEndpointTests(APITestCase):
	def _mk_user(self, *, email: str, phone: str, name: str):
		user = User(email=email, phone=phone, name=name)
		user.set_password('pass1234')
		user.save()
		return user

	@patch('api.views.send_mailgun_email')
	def test_nudge_endpoint_is_public_and_idempotent(self, mock_send_mailgun_email):
		url = reverse('cron-nudge-inactive-users')
		now = datetime(2026, 4, 25, 12, 0, 0, tzinfo=dt_timezone.utc)

		inactive = self._mk_user(email='inactive@test.com', phone='+10000000041', name='Inactive')
		active = self._mk_user(email='active@test.com', phone='+10000000042', name='Active')

		with patch('django.utils.timezone.now', return_value=now):
			UserDailyActivity.objects.create(
				user=inactive,
				activity_date=(now - timedelta(days=15)).date(),
				first_activity_at=now - timedelta(days=15),
				last_activity_at=now - timedelta(days=15),
				source='seed',
			)
			UserDailyActivity.objects.create(
				user=active,
				activity_date=(now - timedelta(days=2)).date(),
				first_activity_at=now - timedelta(days=2),
				last_activity_at=now - timedelta(days=2),
				source='seed',
			)

			resp1 = self.client.post(url)

		self.assertEqual(resp1.status_code, status.HTTP_200_OK)
		self.assertEqual(resp1.data['threshold_days'], 14)
		self.assertEqual(resp1.data['nudged_count'], 1)
		self.assertEqual(resp1.data['failed_count'], 0)
		self.assertEqual(resp1.data['skipped_count'], 0)
		self.assertEqual(mock_send_mailgun_email.call_count, 1)
		called_kwargs = mock_send_mailgun_email.call_args.kwargs
		self.assertEqual(called_kwargs['to_email'], 'inactive@test.com')
		self.assertIn('We miss you at Padlupp', called_kwargs['subject'])
		self.assertIn('Padlupp', called_kwargs['text'])

		with patch('django.utils.timezone.now', return_value=now):
			resp2 = self.client.post(url)

		self.assertEqual(resp2.status_code, status.HTTP_200_OK)
		self.assertEqual(resp2.data['nudged_count'], 0)
		self.assertEqual(resp2.data['skipped_count'], 1)
		self.assertEqual(mock_send_mailgun_email.call_count, 1)
		self.assertTrue(
			InactivityNudgeLog.objects.filter(
				user=inactive,
				threshold_days=14,
			).exists()
		)


@override_settings(
	CACHES={
		'default': {
			'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
			'LOCATION': 'presence-tests',
		}
	}
)
class ChatPresenceTests(TransactionTestCase):
	def setUp(self):
		cache.clear()
		self.user = User.objects.create_user(
			email='presence@test.com',
			phone='+10000000049',
			name='Presence',
			password='pass1234',
		)
		self.partner = User.objects.create_user(
			email='presence-partner@test.com',
			phone='+10000000050',
			name='Partner',
			password='pass1234',
		)
		partnership = Partnership.objects.create(user_a=self.user, user_b=self.partner)
		self.conversation = Conversation.objects.create(partnership=partnership)
		self.consumer = ChatConsumer()

	def tearDown(self):
		cache.clear()
		super().tearDown()

	def test_last_seen_updates_only_after_final_connection_closes(self):
		set_presence = async_to_sync(self.consumer.set_user_online)
		get_online_ids = async_to_sync(self.consumer.get_online_user_ids)

		set_presence(self.user.id, self.conversation.id, True, 'channel-a')
		set_presence(self.user.id, self.conversation.id, True, 'channel-b')
		set_presence(self.user.id, self.conversation.id, False, 'channel-a')

		self.user.refresh_from_db()
		self.assertIsNone(self.user.last_seen_at)
		self.assertEqual(get_online_ids(self.conversation.id), [self.user.id])

		disconnected_at = datetime(2026, 6, 7, 12, 0, tzinfo=dt_timezone.utc)
		with patch('api.consumers.timezone.now', return_value=disconnected_at):
			set_presence(self.user.id, self.conversation.id, False, 'channel-b')

		self.user.refresh_from_db()
		self.assertEqual(self.user.last_seen_at, disconnected_at)
		self.assertEqual(get_online_ids(self.conversation.id), [])

	def test_last_seen_snapshot_survives_presence_cache_clear(self):
		last_seen_at = datetime(2026, 6, 6, 9, 30, tzinfo=dt_timezone.utc)
		User.objects.filter(id=self.partner.id).update(last_seen_at=last_seen_at)
		cache.clear()

		last_seen = async_to_sync(self.consumer.get_last_seen_at_by_user_id)(self.conversation.id)

		self.assertEqual(last_seen[str(self.partner.id)], last_seen_at.isoformat())

	def test_stale_connection_is_pruned_and_saved_as_last_seen(self):
		heartbeat_at = timezone.now() - timedelta(minutes=5)
		cache.set(
			self.consumer._presence_cache_key(self.conversation.id),
			{str(self.user.id): {'abandoned-channel': heartbeat_at.isoformat()}},
			timeout=None,
		)

		online_ids = async_to_sync(self.consumer.get_online_user_ids)(self.conversation.id)

		self.user.refresh_from_db()
		self.assertEqual(online_ids, [])
		self.assertEqual(self.user.last_seen_at, heartbeat_at)


class CheckinReminderCronEndpointTests(APITestCase):
	def _mk_user(self, *, email: str, phone: str, name: str):
		user = User(email=email, phone=phone, name=name)
		user.set_password('pass1234')
		user.save()
		return user

	@patch('api.views.send_mailgun_email')
	def test_checkin_reminders_due_tomorrow_and_idempotent(self, mock_send_mailgun_email):
		url = reverse('cron-checkin-reminders')
		now = datetime(2026, 4, 25, 10, 0, 0, tzinfo=dt_timezone.utc)  # Saturday

		owner = self._mk_user(email='owner-goal@test.com', phone='+10000000051', name='Owner')
		partner = self._mk_user(email='partner-goal@test.com', phone='+10000000052', name='Partner')
		partnership = Partnership.objects.create(user_a=owner, user_b=partner)

		sunday_goal = Goal.objects.create(
			user=owner,
			partnership=partnership,
			title='Sunday Checkin Goal',
			checkin_frequency=Goal.CHECKIN_SUNDAYS,
		)
		three_day_goal = Goal.objects.create(
			user=owner,
			title='3 Day Goal',
			checkin_frequency=Goal.CHECKIN_3_DAYS,
		)

		# Anchor three_day_goal so tomorrow is exactly on the cadence.
		Goal.objects.filter(id=three_day_goal.id).update(created_at=now - timedelta(days=2))
		three_day_goal.refresh_from_db()

		with patch('django.utils.timezone.now', return_value=now):
			resp1 = self.client.post(url)

		self.assertEqual(resp1.status_code, status.HTTP_200_OK)
		self.assertEqual(resp1.data['goals_due_tomorrow'], 2)
		# The owner gets one digest for both goals; the partner gets one email.
		self.assertEqual(resp1.data['emails_sent'], 2)
		self.assertEqual(resp1.data['emails_failed'], 0)
		self.assertEqual(mock_send_mailgun_email.call_count, 2)
		owner_email = next(
			call.kwargs for call in mock_send_mailgun_email.call_args_list
			if call.kwargs['to_email'] == owner.email
		)
		self.assertIn('Sunday Checkin Goal', owner_email['text'])
		self.assertIn('3 Day Goal', owner_email['text'])
		self.assertIn('Your 2 Padlupp check-in reminders', owner_email['subject'])
		self.assertEqual(CheckinReminderLog.objects.filter(user=owner).count(), 2)

		with patch('django.utils.timezone.now', return_value=now):
			resp2 = self.client.post(url)

		self.assertEqual(resp2.status_code, status.HTTP_200_OK)
		self.assertEqual(resp2.data['goals_due_tomorrow'], 2)
		self.assertEqual(resp2.data['emails_sent'], 0)
		self.assertEqual(resp2.data['emails_skipped'], 3)
		self.assertEqual(mock_send_mailgun_email.call_count, 2)
		self.assertEqual(
			CheckinReminderLog.objects.filter(goal=sunday_goal, reminder_for_date=(now.date() + timedelta(days=1))).count(),
			2,
		)

	@patch('api.views.send_mailgun_email', side_effect=EmailSendError('send failed'))
	def test_failed_digest_does_not_log_reminders(self, mock_send_mailgun_email):
		url = reverse('cron-checkin-reminders')
		now = datetime(2026, 4, 25, 10, 0, 0, tzinfo=dt_timezone.utc)
		owner = self._mk_user(email='retry@test.com', phone='+10000000053', name='Retry')

		for title in ('First Goal', 'Second Goal'):
			Goal.objects.create(
				user=owner,
				title=title,
				checkin_frequency=Goal.CHECKIN_SUNDAYS,
			)

		with patch('django.utils.timezone.now', return_value=now):
			response = self.client.post(url)

		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.assertEqual(response.data['emails_sent'], 0)
		self.assertEqual(response.data['emails_failed'], 1)
		self.assertEqual(mock_send_mailgun_email.call_count, 1)
		self.assertEqual(CheckinReminderLog.objects.filter(user=owner).count(), 0)


class TaskVisibilityTests(APITestCase):
	def _mk_user(self, *, email: str, phone: str, name: str, password: str = 'pass1234'):
		user = User(email=email, phone=phone, name=name)
		user.set_password(password)
		user.save()
		return user

	def _results(self, resp):
		# DRF pagination is enabled globally; handle both paginated and non-paginated.
		return resp.data.get('results', resp.data)

	def setUp(self):
		self.owner = self._mk_user(email='owner@test.com', name='Owner', phone='+10000000031')
		self.partner = self._mk_user(email='partner@test.com', name='Partner', phone='+10000000032')
		self.stranger = self._mk_user(email='stranger@test.com', name='Stranger', phone='+10000000033')

		user_a, user_b = sorted([self.owner, self.partner], key=lambda u: u.id)
		self.partnership = Partnership.objects.create(user_a=user_a, user_b=user_b)

		self.shared_goal = Goal.objects.create(user=self.owner, partnership=self.partnership, title='Shared Goal')
		self.private_goal = Goal.objects.create(user=self.owner, title='Private Goal')

		# Task visible to partner via goal partnership (task.partnership left NULL intentionally).
		self.task_via_goal_partnership = Task.objects.create(
			goal=self.shared_goal,
			owner=self.owner,
			title='Task A',
		)
		# Task visible to partner via explicit task partnership.
		self.task_via_task_partnership = Task.objects.create(
			goal=self.private_goal,
			partnership=self.partnership,
			owner=self.owner,
			title='Task B',
		)

	def test_partner_can_list_and_retrieve_shared_tasks(self):
		self.client.force_authenticate(user=self.partner)
		list_url = reverse('tasks-list')
		resp = self.client.get(list_url)
		self.assertEqual(resp.status_code, status.HTTP_200_OK)
		ids = {row['id'] for row in self._results(resp)}
		self.assertIn(self.task_via_goal_partnership.id, ids)
		self.assertIn(self.task_via_task_partnership.id, ids)

		detail_url = reverse('tasks-detail', kwargs={'pk': self.task_via_goal_partnership.id})
		detail = self.client.get(detail_url)
		self.assertEqual(detail.status_code, status.HTTP_200_OK)
		self.assertEqual(detail.data['id'], self.task_via_goal_partnership.id)

	def test_partner_cannot_modify_task_via_default_update(self):
		self.client.force_authenticate(user=self.partner)
		detail_url = reverse('tasks-detail', kwargs={'pk': self.task_via_goal_partnership.id})
		resp = self.client.patch(detail_url, data={'title': 'Hacked'}, format='json')
		self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

	def test_stranger_cannot_see_partner_tasks(self):
		self.client.force_authenticate(user=self.stranger)
		list_url = reverse('tasks-list')
		resp = self.client.get(list_url)
		self.assertEqual(resp.status_code, status.HTTP_200_OK)
		ids = {row['id'] for row in self._results(resp)}
		self.assertNotIn(self.task_via_goal_partnership.id, ids)
		self.assertNotIn(self.task_via_task_partnership.id, ids)

	def test_cannot_create_task_for_inaccessible_goal(self):
		self.client.force_authenticate(user=self.partner)
		list_url = reverse('tasks-list')
		payload = {'goal': self.private_goal.id, 'title': 'Nope'}
		resp = self.client.post(list_url, data=payload, format='json')
		self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
		self.assertIn('goal', resp.data)


class ForgotPasswordFlowTests(APITestCase):
	def _mk_user(self, *, email: str, phone: str, name: str, password: str = 'pass1234'):
		user = User(email=email, phone=phone, name=name)
		user.set_password(password)
		user.save()
		return user

	@patch('api.viewsets.send_mailgun_email')
	def test_request_otp_rejects_unknown_email(self, mock_send_mailgun_email):
		url = reverse('auth-forgot-password-request-otp')
		resp = self.client.post(url, data={'email': 'missing@test.com'}, format='json')
		self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
		mock_send_mailgun_email.assert_not_called()

	@patch('api.viewsets._generate_password_reset_token', return_value='reset-token-abc')
	@patch('api.viewsets._generate_password_reset_otp', return_value='123456')
	@patch('api.viewsets.send_mailgun_email')
	def test_full_forgot_password_flow(self, mock_send_mailgun_email, mock_gen_otp, mock_gen_token):
		user = self._mk_user(email='fp@test.com', phone='+10000000999', name='FP', password='oldpass123')

		request_url = reverse('auth-forgot-password-request-otp')
		resp1 = self.client.post(request_url, data={'email': 'fp@test.com'}, format='json')
		self.assertEqual(resp1.status_code, status.HTTP_200_OK)
		mock_send_mailgun_email.assert_called()

		verify_url = reverse('auth-forgot-password-verify-otp')
		resp2 = self.client.post(verify_url, data={'email': 'fp@test.com', 'otp': '123456'}, format='json')
		self.assertEqual(resp2.status_code, status.HTTP_200_OK)
		self.assertEqual(resp2.data.get('reset_token'), 'reset-token-abc')

		reset_url = reverse('auth-forgot-password-reset-password')
		resp3 = self.client.post(
			reset_url,
			data={'reset_token': 'reset-token-abc', 'new_password': 'newpass123', 'confirm_password': 'newpass123'},
			format='json',
		)
		self.assertEqual(resp3.status_code, status.HTTP_200_OK)

		user.refresh_from_db()
		self.assertTrue(user.check_password('newpass123'))


@override_settings(BETA_WAITLIST_ONLY=False)
class GoogleAuthEndpointsTests(APITestCase):
	def setUp(self):
		# Ensure the setting is present for token audience verification.
		settings.GOOGLE_OAUTH2_CLIENT_ID = 'test-client-id.apps.googleusercontent.com'

	def test_google_signup_creates_user_profile_and_token(self):
		url = reverse('auth-google-signup')

		with patch('api.viewsets.google_id_token.verify_oauth2_token') as verify:
			verify.return_value = {
				'email': 'newuser@test.com',
				'email_verified': True,
				'name': 'New User',
				'sub': 'google-sub-123',
			}
			resp = self.client.post(url, data={'id_token': 'dummy'}, format='json')

		self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
		self.assertIn('token', resp.data)
		self.assertEqual(resp.data['user']['email'], 'newuser@test.com')
		self.assertTrue(resp.data['user']['email_verified'])
		self.assertTrue(User.objects.filter(email='newuser@test.com').exists())
		user = User.objects.get(email='newuser@test.com')
		self.assertTrue(Profile.objects.filter(user=user).exists())

	def test_google_signup_rejects_existing_email(self):
		User.objects.create(email='exists@test.com', name='Exists')
		url = reverse('auth-google-signup')

		with patch('api.viewsets.google_id_token.verify_oauth2_token') as verify:
			verify.return_value = {'email': 'exists@test.com', 'email_verified': True, 'name': 'Exists'}
			resp = self.client.post(url, data={'id_token': 'dummy'}, format='json')

		self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

	def test_google_signin_logs_in_existing_user(self):
		user = User.objects.create(email='me@test.com', name='Me', email_verified=False)
		Profile.objects.get_or_create(user=user)
		url = reverse('auth-google-signin')
		fixed_now = datetime(2026, 1, 3, 15, 0, 0, tzinfo=dt_timezone.utc)

		with patch('api.viewsets.google_id_token.verify_oauth2_token') as verify:
			with patch('django.utils.timezone.now', return_value=fixed_now):
				verify.return_value = {'email': 'me@test.com', 'email_verified': True, 'name': 'Me'}
				resp = self.client.post(url, data={'id_token': 'dummy'}, format='json')

		self.assertEqual(resp.status_code, status.HTTP_200_OK)
		self.assertIn('token', resp.data)
		user.refresh_from_db()
		self.assertTrue(user.email_verified)
		self.assertEqual(user.last_login, fixed_now)

	def test_google_signin_rejects_nonexistent_user(self):
		url = reverse('auth-google-signin')

		with patch('api.viewsets.google_id_token.verify_oauth2_token') as verify:
			verify.return_value = {'email': 'missing@test.com', 'email_verified': True, 'name': 'Missing'}
			resp = self.client.post(url, data={'id_token': 'dummy'}, format='json')

		self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

	def test_google_auth_signs_up_when_missing(self):
		url = reverse('auth-google-auth')

		with patch('api.viewsets.google_id_token.verify_oauth2_token') as verify:
			verify.return_value = {
				'email': 'combo-new@test.com',
				'email_verified': True,
				'name': 'Combo New',
			}
			resp = self.client.post(url, data={'id_token': 'dummy'}, format='json')

		self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
		self.assertTrue(User.objects.filter(email='combo-new@test.com').exists())
		user = User.objects.get(email='combo-new@test.com')
		self.assertTrue(Profile.objects.filter(user=user).exists())
		self.assertIn('token', resp.data)

	def test_google_auth_signs_in_when_exists(self):
		user = User.objects.create(email='combo-exists@test.com', name='Combo Exists', email_verified=False)
		Profile.objects.get_or_create(user=user)
		url = reverse('auth-google-auth')

		with patch('api.viewsets.google_id_token.verify_oauth2_token') as verify:
			verify.return_value = {
				'email': 'combo-exists@test.com',
				'email_verified': True,
				'name': 'Combo Exists',
			}
			resp = self.client.post(url, data={'id_token': 'dummy'}, format='json')

		self.assertEqual(resp.status_code, status.HTTP_200_OK)
		self.assertIn('token', resp.data)
		user.refresh_from_db()
		self.assertTrue(user.email_verified)


class AvatarAbsoluteUrlTests(APITestCase):
	"""Tests for absolute avatar URLs in HTTP and websocket serializer payloads."""

	def _mk_user_with_avatar(self, *, email: str = 'av@test.com', name: str = 'Av') -> User:
		# 1x1 PNG
		png_bytes = base64.b64decode(
			'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMB/6XhYQAAAABJRU5ErkJggg=='
		)
		avatar_file = SimpleUploadedFile('avatar.png', png_bytes, content_type='image/png')
		user = User.objects.create(email=email, name=name)
		user.avatar = avatar_file
		user.save()
		return user

	def test_user_serializer_avatar_is_absolute_with_request_context(self):
		with tempfile.TemporaryDirectory() as tmpdir:
			with override_settings(MEDIA_ROOT=tmpdir):
				user = self._mk_user_with_avatar(email='abs1@test.com')
				factory = APIRequestFactory()
				request = factory.get('/')
				data = UserSerializer(user, context={'request': request}).data
				self.assertIsInstance(data.get('avatar'), str)
				self.assertTrue(data['avatar'].startswith('http://testserver/'))
				self.assertIn('/assets/avatars/', data['avatar'])

	def test_user_serializer_avatar_uses_public_base_url_without_request(self):
		with tempfile.TemporaryDirectory() as tmpdir:
			with override_settings(MEDIA_ROOT=tmpdir, PUBLIC_BASE_URL='https://api.padlupp.com'):
				user = self._mk_user_with_avatar(email='abs2@test.com')
				data = UserSerializer(user, context={}).data
				self.assertIsInstance(data.get('avatar'), str)
				self.assertTrue(data['avatar'].startswith('https://api.padlupp.com/'))

	def test_scope_request_builds_absolute_uri(self):
		scope = {
			'scheme': 'https',
			'headers': [(b'host', b'example.com')],
		}
		req = _ScopeRequest(scope)
		self.assertEqual(req.build_absolute_uri('/assets/avatars/x.png'), 'https://example.com/assets/avatars/x.png')
		self.assertEqual(req.build_absolute_uri('https://cdn.example.com/a.png'), 'https://cdn.example.com/a.png')

	def test_message_serializer_sender_avatar_is_absolute_in_websocket_context(self):
		with tempfile.TemporaryDirectory() as tmpdir:
			with override_settings(MEDIA_ROOT=tmpdir):
				sender = self._mk_user_with_avatar(email='sender@test.com')
				# Create minimal conversation graph
				other = User.objects.create(email='other2@test.com', name='Other2')
				user_a, user_b = sorted([sender, other], key=lambda u: u.id)
				partnership = Partnership.objects.create(user_a=user_a, user_b=user_b)
				conv = Conversation.objects.create(partnership=partnership)
				msg = Message.objects.create(conversation=conv, sender=sender, text='hi')

				scope = {'scheme': 'https', 'headers': [(b'host', b'ws.example.com')]}
				req = _ScopeRequest(scope)
				payload = MessageSerializer(msg, context={'request': req}).data
				self.assertTrue(payload['sender']['avatar'].startswith('https://ws.example.com/'))


class ConversationEndpointsTests(APITestCase):
	def _mk_user(self, *, email: str, name: str, password: str = 'pass1234'):
		user = User(email=email, name=name)
		user.set_password(password)
		user.save()
		Profile.objects.get_or_create(user=user)
		return user

	def setUp(self):
		self.user_a = self._mk_user(email='a@test.com', name='A')
		self.user_b = self._mk_user(email='b@test.com', name='B')
		user_a, user_b = sorted([self.user_a, self.user_b], key=lambda u: u.id)
		self.partnership = Partnership.objects.create(user_a=user_a, user_b=user_b)
		self.conversation, _ = Conversation.objects.get_or_create(partnership=self.partnership)

	def test_conversations_list_includes_unread_count(self):
		# Two messages from B -> A, only one unread
		Message.objects.create(conversation=self.conversation, sender=self.user_b, text='hello 1', is_read=False)
		Message.objects.create(conversation=self.conversation, sender=self.user_b, text='hello 2', is_read=True)
		# Message from A -> B should not count as unread for A
		Message.objects.create(conversation=self.conversation, sender=self.user_a, text='reply', is_read=False)

		self.client.force_authenticate(user=self.user_a)
		url = reverse('conversations-list')
		resp = self.client.get(url)
		self.assertEqual(resp.status_code, status.HTTP_200_OK)
		rows = resp.data.get('results', resp.data)
		self.assertEqual(len(rows), 1)
		self.assertEqual(rows[0]['id'], self.conversation.id)
		self.assertEqual(rows[0]['unread_count'], 1)

		# For B, the unread should be the message sent by A
		self.client.force_authenticate(user=self.user_b)
		resp2 = self.client.get(url)
		self.assertEqual(resp2.status_code, status.HTTP_200_OK)
		rows2 = resp2.data.get('results', resp2.data)
		self.assertEqual(len(rows2), 1)
		self.assertEqual(rows2[0]['unread_count'], 1)


class GoalSharingEndpointsTests(APITestCase):
	def _mk_user(self, *, email: str, phone: str, name: str, password: str = 'pass1234'):
		user = User(email=email, phone=phone, name=name)
		user.set_password(password)
		user.save()
		return user

	def setUp(self):
		self.owner = self._mk_user(email='goal-owner@test.com', phone='+10000000061', name='GoalOwner')
		self.member = self._mk_user(email='goal-member@test.com', phone='+10000000062', name='GoalMember')
		self.stranger = self._mk_user(email='goal-stranger@test.com', phone='+10000000063', name='GoalStranger')
		self.client.force_authenticate(user=self.owner)

	def test_public_goal_generates_invite_link(self):
		goal = Goal.objects.create(user=self.owner, title='Public goal', is_public=True)
		goal.refresh_from_db()
		self.assertIsNotNone(goal.shared_id)
		self.assertIsNotNone(goal.invite_link)
		self.assertIn('/goals/?shared_id=', goal.invite_link)

	def test_join_goal_adds_member_and_creates_group_conversation(self):
		goal = Goal.objects.create(user=self.owner, title='Joinable goal', is_public=True)
		goal.refresh_from_db()

		join_url = reverse('goals-join-goal')
		self.client.force_authenticate(user=self.member)
		resp = self.client.post(join_url, data={'shared_id': str(goal.shared_id)}, format='json')
		self.assertEqual(resp.status_code, status.HTTP_200_OK)
		self.assertEqual(resp.data['goal_id'], goal.id)
		self.assertEqual(resp.data['direct_link'], f'https://app.padlupp.com/goals/{goal.id}')

		goal.refresh_from_db()
		self.assertTrue(goal.members.filter(id=self.owner.id).exists())
		self.assertTrue(goal.members.filter(id=self.member.id).exists())
		self.assertTrue(goal.conversation.is_group)
		self.assertSetEqual(set(goal.conversation.members.values_list('id', flat=True)), {self.owner.id, self.member.id})

	@override_settings(
		EMAIL_NOTIFICATIONS_ENABLED=True,
		MAILGUN_API_KEY='test',
		MAILGUN_DOMAIN='test',
		MAILGUN_FROM_EMAIL='no-reply@test.com',
	)
	@patch('api.viewsets.send_mailgun_email')
	def test_join_goal_emails_goal_owner(self, mock_send_mailgun_email):
		goal = Goal.objects.create(user=self.owner, title='Email goal', is_public=True)
		goal.refresh_from_db()

		join_url = reverse('goals-join-goal')
		self.client.force_authenticate(user=self.member)
		resp = self.client.post(join_url, data={'shared_id': str(goal.shared_id)}, format='json')
		self.assertEqual(resp.status_code, status.HTTP_200_OK)

		mock_send_mailgun_email.assert_called()
		called_kwargs = mock_send_mailgun_email.call_args.kwargs
		self.assertEqual(called_kwargs.get('to_email'), self.owner.email)
		self.assertIn(self.member.name, called_kwargs.get('subject', ''))
		text = called_kwargs.get('text', '')
		self.assertIn(self.member.name, text)
		self.assertIn(f'https://app.padlupp.com/goals/{goal.id}', text)

	@patch('api.viewsets.send_mailgun_email')
	def test_share_goal_adds_existing_users_and_invites_unknown_emails(self, mock_send_mailgun_email):
		goal = Goal.objects.create(user=self.owner, title='Shared goal', is_public=True)
		share_url = reverse('goals-share', kwargs={'pk': goal.id})
		resp = self.client.post(
			share_url,
			data={'emails': [self.member.email, 'new-person@example.com'], 'message': 'Join me on this goal.'},
			format='json',
		)
		self.assertEqual(resp.status_code, status.HTTP_200_OK)
		self.assertEqual(resp.data['goal_id'], goal.id)
		self.assertIn(self.member.id, resp.data['added_user_ids'])
		self.assertIn('new-person@example.com', resp.data['invited_emails'])
		self.assertTrue(goal.members.filter(id=self.member.id).exists())
		self.assertTrue(Notification.objects.filter(user=self.member, type='goal_shared').exists())
		self.assertTrue(Waitlister.objects.filter(email='new-person@example.com').exists())
		self.assertGreaterEqual(mock_send_mailgun_email.call_count, 2)

	def test_goal_detail_does_not_error_with_multiple_members(self):
		goal = Goal.objects.create(user=self.owner, title='Detail goal')
		# Create multiple membership rows so the underlying ORM join would
		# produce duplicate Goal rows without a distinct() queryset.
		goal.members.add(self.owner, self.member, self.stranger)

		self.client.force_authenticate(user=self.owner)
		url = reverse('goals-detail', kwargs={'pk': goal.id})
		resp = self.client.get(url)
		self.assertEqual(resp.status_code, status.HTTP_200_OK)
		self.assertEqual(resp.data['id'], goal.id)

	def test_group_conversation_can_be_renamed_by_member(self):
		goal = Goal.objects.create(user=self.owner, title='Renameable goal', is_public=True)
		join_url = reverse('goals-join-goal')
		self.client.force_authenticate(user=self.member)
		join_resp = self.client.post(join_url, data={'shared_id': str(goal.shared_id)}, format='json')
		self.assertEqual(join_resp.status_code, status.HTTP_200_OK)

		conversation = goal.conversation
		self.assertTrue(conversation.is_group)
		self.assertEqual(conversation.name, 'Renameable goal')

		rename_url = reverse('conversations-rename-group', kwargs={'pk': conversation.id})
		resp = self.client.post(rename_url, data={'name': 'Daily Wins'}, format='json')
		self.assertEqual(resp.status_code, status.HTTP_200_OK)
		self.assertEqual(resp.data['name'], 'Daily Wins')
		conversation.refresh_from_db()
		self.assertEqual(conversation.name, 'Daily Wins')

	def test_goal_members_endpoint_is_restricted_to_goal_members(self):
		goal = Goal.objects.create(user=self.owner, title='Members goal')
		goal.members.add(self.member)

		url = reverse('goals-members', kwargs={'pk': goal.id})

		self.client.force_authenticate(user=self.owner)
		resp_owner = self.client.get(url)
		self.assertEqual(resp_owner.status_code, status.HTTP_200_OK)
		owner_ids = {row['id'] for row in resp_owner.data}
		self.assertSetEqual(owner_ids, {self.owner.id, self.member.id})

		self.client.force_authenticate(user=self.member)
		resp_member = self.client.get(url)
		self.assertEqual(resp_member.status_code, status.HTTP_200_OK)

		self.client.force_authenticate(user=self.stranger)
		resp_stranger = self.client.get(url)
		# Depending on queryset filtering, this may be 403 or 404.
		self.assertIn(resp_stranger.status_code, [status.HTTP_403_FORBIDDEN, status.HTTP_404_NOT_FOUND])

	def test_goal_owner_can_remove_members(self):
		goal = Goal.objects.create(user=self.owner, title='Remove member goal')
		# Create membership rows via the through model so GoalMembership post_save
		# signals run (goal.members.add uses bulk_create and won't trigger post_save).
		GoalMembership.objects.get_or_create(goal=goal, user=self.owner, defaults={'added_by': self.owner})
		GoalMembership.objects.get_or_create(goal=goal, user=self.member, defaults={'added_by': self.owner})
		conversation_id = goal.conversation.id

		remove_url = reverse('goals-remove-member', kwargs={'pk': goal.id, 'user_id': self.member.id})

		# Non-owner cannot remove
		self.client.force_authenticate(user=self.member)
		forbidden = self.client.delete(remove_url)
		self.assertEqual(forbidden.status_code, status.HTTP_403_FORBIDDEN)

		# Owner removes member
		self.client.force_authenticate(user=self.owner)
		ok = self.client.delete(remove_url)
		self.assertEqual(ok.status_code, status.HTTP_200_OK)
		goal.refresh_from_db()
		self.assertFalse(goal.members.filter(id=self.member.id).exists())

		conversation = Conversation.objects.get(id=conversation_id)
		self.assertFalse(conversation.members.filter(id=self.member.id).exists())

		# Removed member no longer has access to the goal
		self.client.force_authenticate(user=self.member)
		detail_url = reverse('goals-detail', kwargs={'pk': goal.id})
		detail = self.client.get(detail_url)
		self.assertEqual(detail.status_code, status.HTTP_404_NOT_FOUND)

	def test_goal_owner_cannot_remove_self(self):
		goal = Goal.objects.create(user=self.owner, title='No self removal')
		url = reverse('goals-remove-member', kwargs={'pk': goal.id, 'user_id': self.owner.id})
		self.client.force_authenticate(user=self.owner)
		resp = self.client.delete(url)
		self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)


class ConversationFeatureEndpointsTests(APITestCase):
	def _mk_user(self, *, email: str, phone: str, name: str):
		user = User(email=email, phone=phone, name=name)
		user.set_password('pass1234')
		user.save()
		return user

	def setUp(self):
		self.owner = self._mk_user(email='conv-owner@test.com', phone='+10000000071', name='ConvOwner')
		self.partner = self._mk_user(email='conv-partner@test.com', phone='+10000000072', name='ConvPartner')
		user_a, user_b = sorted([self.owner, self.partner], key=lambda u: u.id)
		self.partnership = Partnership.objects.create(user_a=user_a, user_b=user_b)
		self.conversation, _ = Conversation.objects.get_or_create(partnership=self.partnership)

	def test_reply_to_message_sets_reply_payload(self):
		root = Message.objects.create(conversation=self.conversation, sender=self.partner, text='root message')
		self.client.force_authenticate(user=self.owner)
		url = reverse('messages-list')
		resp = self.client.post(
			url,
			data={'conversation': self.conversation.id, 'text': 'reply message', 'reply_to_message_id': root.id},
			format='json',
		)
		self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
		self.assertTrue(resp.data['is_a_reply'])
		self.assertIsNotNone(resp.data['reply_to'])
		self.assertEqual(resp.data['reply_to']['id'], root.id)

	def test_conversation_media_lists_only_attachments(self):
		text_message = Message.objects.create(conversation=self.conversation, sender=self.owner, text='plain text')
		file_message = Message.objects.create(
			conversation=self.conversation,
			sender=self.partner,
			text='with file',
			attachment=SimpleUploadedFile('evidence.png', b'png-bytes', content_type='image/png'),
			attachment_name='evidence.png',
			attachment_mime='image/png',
			attachment_size=9,
		)
		self.client.force_authenticate(user=self.owner)
		url = reverse('conversations-media', kwargs={'pk': self.conversation.id})
		resp = self.client.get(url)
		self.assertEqual(resp.status_code, status.HTTP_200_OK)
		rows = resp.data.get('results', resp.data) if isinstance(resp.data, dict) else resp.data
		self.assertEqual(len(rows), 1)
		self.assertEqual(rows[0]['sender_id'], self.partner.id)
		self.assertEqual(rows[0]['sender_name'], self.partner.name)
		self.assertIn('http://testserver/', rows[0]['file'])

	def test_buddy_profile_endpoint_returns_other_profile(self):
		Profile.objects.get_or_create(user=self.partner)
		self.client.force_authenticate(user=self.owner)
		url = reverse('buddies-profile', kwargs={'user_id': self.partner.id})
		resp = self.client.get(url)
		self.assertEqual(resp.status_code, status.HTTP_200_OK)
		self.assertEqual(resp.data['user']['id'], self.partner.id)
		self.assertIn('profile', resp.data)
