from django.urls import reverse
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
