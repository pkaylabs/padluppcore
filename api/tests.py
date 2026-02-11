from django.urls import reverse
from unittest.mock import patch
import base64
import tempfile

from django.conf import settings
from django.test import override_settings
from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework.test import APIRequestFactory

from accounts.models import User
from api.models import BuddyRequest, Partnership, Profile, Conversation, Message
from api.serializers import UserSerializer, MessageSerializer
from api.consumers import _ScopeRequest
from django.core.files.uploadedfile import SimpleUploadedFile


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

	def test_connect_and_invitations_accept_flow_creates_partnership(self):
		connect_url = reverse('buddies-connect')
		resp = self.client.post(connect_url, data={'to_user': self.other.id, 'message': 'Hey, want to connect?'}, format='json')
		self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
		self.assertEqual(resp.data['status'], BuddyRequest.STATUS_PENDING)
		self.assertEqual(resp.data['message'], 'Hey, want to connect?')

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

		# Partnership exists
		user_a, user_b = sorted([self.user, self.other], key=lambda u: u.id)
		self.assertTrue(Partnership.objects.filter(user_a=user_a, user_b=user_b).exists())

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

	def test_update_user_duplicate_phone_rejected(self):
		# Other user owns this phone
		other = User(email='dup@test.com', phone='+19998887777', name='Dup')
		other.set_password('pass1234')
		other.save()

		url = reverse('auth-user')
		resp = self.client.patch(url, data={'phone': '+19998887777'}, format='json')
		self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)


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

		with patch('api.viewsets.google_id_token.verify_oauth2_token') as verify:
			verify.return_value = {'email': 'me@test.com', 'email_verified': True, 'name': 'Me'}
			resp = self.client.post(url, data={'id_token': 'dummy'}, format='json')

		self.assertEqual(resp.status_code, status.HTTP_200_OK)
		self.assertIn('token', resp.data)
		user.refresh_from_db()
		self.assertTrue(user.email_verified)

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
