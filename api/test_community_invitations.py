from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import override_settings
from django.utils import timezone
from rest_framework.test import APITestCase

from .community_models import CommunityAudit, CommunityCategory, CommunityInvite
from .community_services import create_group, join_group, manage_group_member
from .models import Notification


@override_settings(SECURE_SSL_REDIRECT=False, ALLOWED_HOSTS=['testserver'],
                   EMAIL_NOTIFICATIONS_ENABLED=False, FIREBASE_PUSH_ENABLED=False)
class GroupInvitationTests(APITestCase):
    def setUp(self):
        User = get_user_model()
        self.owner = User.objects.create(email='invite-owner@example.test', name='Owner', is_founder=True)
        self.admin = User.objects.create(email='invite-admin@example.test', name='Admin')
        self.member = User.objects.create(email='invite-member@example.test', name='Member')
        self.moderator = User.objects.create(email='invite-mod@example.test', name='Moderator')
        self.invitee = User.objects.create(email='invite-recipient@example.test', name='Invitee')
        self.outsider = User.objects.create(email='invite-outsider@example.test', name='Outside')
        self.category = CommunityCategory.objects.get(name='Educational')
        self.group = self.make_group()
        manage_group_member(self.group, self.owner, self.admin, 'invite', role='admin')
        join_group(self.group, self.admin)
        for user in (self.member, self.moderator):
            join_group(self.group, user)
        manage_group_member(self.group, self.owner, self.moderator, 'role', role='moderator')
        self.client.force_authenticate(self.admin)

    def make_group(self):
        return create_group(self.owner, {'name': 'Reading group', 'description': 'Read together',
                                         'category': self.category, 'visibility': 'public'})

    def invite(self, group=None, role='member'):
        return manage_group_member(group or self.group, self.owner, self.invitee, 'invite', role=role)

    def path(self, group=None):
        return f'/api-v1/community/groups/{(group or self.group).id}/invitations/'

    def revoke(self, invitation, expected=200, group=None):
        response = self.client.post(self.path(group), {'invitation_id': invitation.id, 'action': 'revoke'}, format='json')
        self.assertEqual(response.status_code, expected, response.data)
        return response

    def test_admin_can_list_and_revoke_another_admins_direct_invitation(self):
        invitation = self.invite(role='moderator')
        result = self.client.get(self.path())
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.data['count'], 1)
        row = result.data['results'][0]
        self.assertEqual(row['id'], invitation.id)
        self.assertEqual(row['user']['id'], self.invitee.id)
        self.assertEqual(row['invited_by']['id'], self.owner.id)
        self.assertEqual(row['role'], 'moderator')
        self.assertFalse(row['is_link'])
        self.assertIsNone(row['url'])
        self.assertNotIn('token', row)
        self.assertIn('expires_at', row)
        response = self.revoke(invitation)
        self.assertEqual(response.data['status'], 'revoked')
        invitation.refresh_from_db()
        self.assertEqual(invitation.status, 'revoked')
        self.assertEqual(self.client.get(self.path()).data['count'], 0)
        event = CommunityAudit.objects.get(action='group.invitation.revoked', target_id=str(invitation.id))
        self.assertEqual(event.actor_id, self.admin.id)
        self.assertEqual(event.group_id, self.group.id)
        self.assertEqual(event.outcome['user_id'], self.invitee.id)
        self.assertTrue(Notification.objects.filter(user=self.invitee, type='community_invitation_revoked').exists())

    def test_revoked_direct_token_cannot_join_or_respond_accept_and_disappears_from_context(self):
        invitation = self.invite()
        self.revoke(invitation)
        self.client.force_authenticate(self.invitee)
        context = self.client.get('/api-v1/community/groups/context/').data
        self.assertNotIn(invitation.id, [row['id'] for row in context['invitations']])
        for route in ('join', 'respond-invitation'):
            response = self.client.post(f'/api-v1/community/groups/{self.group.id}/{route}/',
                                        {'token': str(invitation.token), 'decision': 'accept'}, format='json')
            self.assertEqual(response.status_code, 400, response.data)
        self.assertFalse(self.group.memberships.filter(user=self.invitee).exists())

    def test_admin_invitation_revocation_does_not_bypass_two_admin_gate(self):
        group = self.make_group()
        invitation = self.invite(group, role='admin')
        self.client.force_authenticate(self.owner)
        self.revoke(invitation, group=group)
        self.client.force_authenticate(self.invitee)
        response = self.client.post(f'/api-v1/community/groups/{group.id}/join/', {}, format='json')
        self.assertEqual(response.status_code, 400)
        self.assertFalse(group.memberships.filter(user=self.invitee).exists())

    def test_shareable_link_is_listed_and_revoke_blocks_future_use_not_existing_members(self):
        response = self.client.post(f'/api-v1/community/groups/{self.group.id}/invite-link/', {}, format='json')
        self.assertEqual(response.status_code, 200)
        invitation = CommunityInvite.objects.get(pk=response.data['id'])
        listed = self.client.get(self.path()).data['results'][0]
        self.assertTrue(listed['is_link'])
        self.assertIsNone(listed['user'])
        self.assertEqual(listed['url'], response.data['url'])
        self.client.force_authenticate(self.invitee)
        joined = self.client.post(f'/api-v1/community/groups/{self.group.id}/join/',
                                  {'token': str(invitation.token)}, format='json')
        self.assertEqual(joined.status_code, 200)
        self.client.force_authenticate(self.admin)
        self.revoke(invitation)
        self.client.force_authenticate(self.outsider)
        rejected = self.client.post(f'/api-v1/community/groups/{self.group.id}/join/',
                                    {'token': str(invitation.token)}, format='json')
        self.assertEqual(rejected.status_code, 400)
        self.assertTrue(self.group.memberships.filter(user=self.invitee, state='active').exists())

    def test_members_moderators_invitees_and_outsiders_cannot_list_or_revoke(self):
        invitation = self.invite()
        for user in (self.member, self.moderator, self.invitee, self.outsider):
            with self.subTest(user=user.name):
                self.client.force_authenticate(user)
                self.assertEqual(self.client.get(self.path()).status_code, 403)
                self.revoke(invitation, expected=403)
        invitation.refresh_from_db()
        self.assertEqual(invitation.status, 'pending')

    def test_invitation_id_is_scoped_to_the_selected_group(self):
        elsewhere = self.invite(self.make_group())
        self.revoke(elsewhere, expected=404)
        elsewhere.refresh_from_db()
        self.assertEqual(elsewhere.status, 'pending')

    def test_terminal_and_expired_invitations_are_not_changed_or_listed(self):
        for state in ('accepted', 'declined', 'pending'):
            with self.subTest(state=state):
                invitation = self.invite()
                invitation.status = state
                if state == 'pending':
                    invitation.expires_at = timezone.now() - timedelta(seconds=1)
                invitation.save()
                self.revoke(invitation, expected=400)
                invitation.refresh_from_db()
                self.assertEqual(invitation.status, state)
        self.assertEqual(self.client.get(self.path()).data['count'], 0)
        self.assertFalse(CommunityAudit.objects.filter(action='group.invitation.revoked').exists())

    def test_repeated_revoke_is_idempotent_and_does_not_duplicate_audit_or_notification(self):
        invitation = self.invite()
        self.revoke(invitation)
        self.revoke(invitation)
        self.assertEqual(CommunityAudit.objects.filter(action='group.invitation.revoked').count(), 1)
        self.assertEqual(Notification.objects.filter(user=self.invitee, type='community_invitation_revoked').count(), 1)

    def test_accepted_member_is_not_removed_by_attempted_invite_revocation(self):
        invitation = self.invite()
        join_group(self.group, self.invitee, token=str(invitation.token))
        self.revoke(invitation, expected=400)
        self.assertTrue(self.group.memberships.filter(user=self.invitee, state='active').exists())

    def test_invitation_list_is_paginated_and_excludes_other_groups(self):
        other_invitation = self.invite(self.make_group())
        now = timezone.now()
        CommunityInvite.objects.bulk_create([
            CommunityInvite(group=self.group, user=self.invitee, invited_by=self.owner,
                            expires_at=now + timedelta(days=7)) for _ in range(21)
        ])
        first = self.client.get(self.path())
        self.assertEqual(first.data['count'], 21)
        self.assertEqual(len(first.data['results']), 20)
        self.assertIsNotNone(first.data['next'])
        second = self.client.get(self.path(), {'page': 2})
        self.assertEqual(len(second.data['results']), 1)
        ids = [item['id'] for item in first.data['results'] + second.data['results']]
        self.assertEqual(len(set(ids)), 21)
        self.assertNotIn(other_invitation.id, ids)

    def test_reinviting_after_revocation_issues_a_new_valid_token(self):
        old = self.invite()
        self.revoke(old)
        new = self.invite()
        self.assertNotEqual(old.token, new.token)
        self.client.force_authenticate(self.invitee)
        response = self.client.post(f'/api-v1/community/groups/{self.group.id}/join/',
                                    {'token': str(new.token)}, format='json')
        self.assertEqual(response.status_code, 200)
        old.refresh_from_db()
        self.assertEqual(old.status, 'revoked')

    def test_internal_admin_can_revoke_without_group_membership(self):
        internal = get_user_model().objects.create(email='invite-internal@example.test', name='Internal', is_staff=True)
        invitation = self.invite()
        self.client.force_authenticate(internal)
        self.assertEqual(self.client.get(self.path()).status_code, 200)
        self.revoke(invitation)

    def test_disabled_admin_and_missing_authentication_are_rejected(self):
        invitation = self.invite()
        self.admin.is_active = False
        self.admin.save(update_fields=['is_active'])
        self.assertIn(self.client.get(self.path()).status_code, (403, 404))
        self.assertIn(self.client.post(self.path(), {'invitation_id': invitation.id, 'action': 'revoke'},
                                       format='json').status_code, (403, 404))
        self.client.force_authenticate(None)
        self.assertEqual(self.client.get(self.path()).status_code, 401)

    def test_revoke_requires_a_valid_id_and_explicit_action(self):
        invitation = self.invite()
        for payload in ({}, {'invitation_id': invitation.id}, {'invitation_id': invitation.id, 'action': 'accept'},
                        {'invitation_id': True, 'action': 'revoke'}, {'invitation_id': 0, 'action': 'revoke'},
                        {'invitation_id': 'invalid', 'action': 'revoke'}):
            with self.subTest(payload=payload):
                response = self.client.post(self.path(), payload, format='json')
                self.assertEqual(response.status_code, 400)
        invitation.refresh_from_db()
        self.assertEqual(invitation.status, 'pending')
