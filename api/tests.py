from django.urls import reverse
from unittest.mock import patch

from django.conf import settings
from rest_framework import status
from rest_framework.test import APITestCase

from accounts.models import User
from api.models import BuddyRequest, Partnership, Profile


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
		resp = self.client.post(connect_url, data={'to_user': self.other.id}, format='json')
		self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
		self.assertEqual(resp.data['status'], BuddyRequest.STATUS_PENDING)

		# Recipient sees it in invitations
		self.client.force_authenticate(user=self.other)
		inv_url = reverse('buddies-invitations')
		inv = self.client.get(inv_url)
		self.assertEqual(inv.status_code, status.HTTP_200_OK)
		self.assertEqual(len(inv.data), 1)
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
