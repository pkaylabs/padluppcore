from datetime import timedelta
import json
import tempfile
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import override_settings
from django.utils import timezone
from rest_framework.test import APITestCase

from .community_access import can_access_goal, can_post_group, can_read_group, can_write_goal, is_internal, visible_messages
from .community_models import CommunityAudit, CommunityCategory, CommunityGroup, CommunityInactivityReview, CommunityMembership, CommunityReport, CommunityTask
from .community_services import generate_task_cycles, review_inactive_members, task_due_dates
from .models import ContentReport, Conversation, ConversationMembership, Goal, GoalCheckin, GoalMembership, Message, Notification, UserAward, UserBlock


@override_settings(SECURE_SSL_REDIRECT=False, ALLOWED_HOSTS=['testserver'], EMAIL_NOTIFICATIONS_ENABLED=False, FIREBASE_PUSH_ENABLED=False)
class CommunityDomainTests(APITestCase):
    def setUp(self):
        User = get_user_model()
        self.founder = User.objects.create(email='founder@example.test', name='Founder', is_founder=True)
        self.admin = User.objects.create(email='admin@example.test', name='Second admin')
        self.member = User.objects.create(email='member@example.test', name='Member')
        self.other = User.objects.create(email='other@example.test', name='Outside member')
        self.category = CommunityCategory.objects.get(name='Educational')
        self.login(self.founder)

    def login(self, user):
        self.client.force_authenticate(user)

    def post(self, path, data=None, expected=200):
        response = self.client.post('/api-v1/community/' + path, data or {}, format='json')
        self.assertEqual(response.status_code, expected, getattr(response, 'data', None))
        return response.data

    def make_group(self, visibility='public', bootstrap=True):
        self.login(self.founder)
        data = self.post('groups/', {'name': 'Book club', 'description': 'Read together', 'category': self.category.id, 'visibility': visibility}, 201)
        group = CommunityGroup.objects.get(pk=data['id'])
        if bootstrap:
            self.post(f'groups/{group.id}/members/', {'user_id': self.admin.id, 'action': 'invite', 'role': 'admin'}, 201)
            self.login(self.admin)
            self.post(f'groups/{group.id}/join/')
            self.login(self.founder)
        return group

    def make_task(self, group, **overrides):
        now = timezone.now()
        data = {'group': group.id, 'title': 'Read a book', 'description': 'Finish together', 'category': 'Educational',
                'start_date': now.date().isoformat(), 'target_date': (now.date() + timedelta(days=14)).isoformat(),
                'invitation_deadline': (now + timedelta(days=2)).isoformat(), 'member_limit': 8,
                'visibility': 'public', 'approval_required': False, 'checkin_frequency': 'DAILY',
                'idempotency_key': 'read-book', 'milestones': [{'title': 'Chapter one'}]}
        data.update(overrides)
        result = self.post('tasks/', data, 201)
        return CommunityTask.objects.get(pk=result['id']), data

    def join_member(self, group, user=None):
        self.login(user or self.member)
        result = self.post(f'groups/{group.id}/join/')
        self.login(self.founder)
        return result

    def test_internal_flags_and_creator_approval_are_distinct(self):
        for flag in ('is_staff', 'is_superuser', 'is_founder'):
            for field in ('is_staff', 'is_superuser', 'is_founder'):
                setattr(self.other, field, field == flag)
            self.assertTrue(is_internal(self.other))
        self.other.is_founder = False
        self.assertFalse(is_internal(self.other))
        self.login(self.member)
        self.post('groups/', {'name': 'Denied', 'category': self.category.id}, 403)
        response = self.client.get('/api-v1/community/hq/overview/')
        self.assertEqual(response.status_code, 404)
        self.login(self.founder)
        self.post('hq/approve-creator/', {'user_id': self.member.id, 'approved': True})
        self.login(self.member)
        group = self.post('groups/', {'name': 'Approved', 'category': self.category.id}, 201)
        self.assertTrue(group['can_manage'])
        self.assertEqual(self.client.get('/api-v1/community/hq/overview/').status_code, 404)

    def test_second_admin_acceptance_bootstraps_join_gate(self):
        group = self.make_group(bootstrap=False)
        self.login(self.member)
        self.post(f'groups/{group.id}/join/', expected=400)
        self.login(self.founder)
        self.post(f'groups/{group.id}/members/', {'user_id': self.admin.id, 'action': 'invite', 'role': 'admin'}, 201)
        self.assertFalse(group.memberships.filter(user=self.admin, state='active').exists())
        self.login(self.admin)
        context = self.client.get('/api-v1/community/groups/context/').data
        self.assertEqual(context['invitations'][0]['role'], 'admin')
        result = self.post(f'groups/{group.id}/join/')
        self.assertEqual(result['admin_count'], 2)
        self.assertEqual(result['membership']['role'], 'admin')
        self.login(self.member)
        self.assertEqual(self.post(f'groups/{group.id}/join/')['membership']['state'], 'active')

    def test_losing_admin_notifies_remaining_and_keeps_existing_chat(self):
        group = self.make_group()
        self.join_member(group)
        self.login(self.admin)
        self.post(f'groups/{group.id}/leave/', {'reason': 'Other priorities'})
        self.assertTrue(Notification.objects.filter(user=self.founder, type='community_admin_required').exists())
        self.assertTrue(can_post_group(group, self.member))
        self.login(self.other)
        self.post(f'groups/{group.id}/join/', expected=400)

    def test_private_request_needs_approval_and_generic_link_does_not_bypass(self):
        group = self.make_group('private')
        link = self.post(f'groups/{group.id}/invite-link/')
        self.login(self.member)
        result = self.post(f'groups/{group.id}/join/', {'token': link['token']})
        self.assertEqual(result['membership']['state'], 'pending')
        self.assertIsNone(result['conversation_id'])
        self.assertFalse(can_read_group(group, self.member))
        self.login(self.founder)
        self.post(f'groups/{group.id}/requests/', {'user_id': self.member.id, 'decision': 'approve'})
        self.assertTrue(can_read_group(group, self.member))

    def test_join_history_window_resources_and_voluntary_absence(self):
        group = self.make_group()
        old = Message.objects.create(conversation=group.conversation, sender=self.founder, text='https://example.test/old')
        Message.objects.filter(pk=old.id).update(created_at=timezone.now() - timedelta(days=40))
        recent = Message.objects.create(conversation=group.conversation, sender=self.founder, text='Recent')
        self.join_member(group)
        qs = Message.objects.filter(conversation=group.conversation)
        self.assertNotIn(old.id, visible_messages(qs, self.member).values_list('id', flat=True))
        self.assertIn(old.id, visible_messages(qs, self.member, resources=True).values_list('id', flat=True))
        self.login(self.member)
        self.post(f'groups/{group.id}/leave/', {'reason': 'Taking a break'})
        absent = Message.objects.create(conversation=group.conversation, sender=self.founder, text='During absence')
        self.assertTrue(can_read_group(group, self.member))
        self.assertFalse(can_post_group(group, self.member))
        self.assertNotIn(absent.id, visible_messages(qs, self.member).values_list('id', flat=True))
        self.post(f'groups/{group.id}/join/')
        self.assertNotIn(absent.id, visible_messages(qs, self.member).values_list('id', flat=True))
        self.assertIn(recent.id, visible_messages(qs, self.member).values_list('id', flat=True))

    def test_removed_member_loses_group_but_keeps_independent_pod(self):
        group = self.make_group()
        self.join_member(group)
        task, _ = self.make_task(group)
        self.login(self.member)
        self.post(f'tasks/{task.id}/join/')
        self.login(self.founder)
        self.post(f'groups/{group.id}/members/', {'user_id': self.member.id, 'action': 'ban', 'reason': 'Rule violation'})
        self.assertFalse(can_read_group(group, self.member))
        self.assertTrue(can_access_goal(task.goal, self.member))
        self.assertTrue(can_write_goal(task.goal, self.member))
        self.login(self.member)
        self.assertEqual(self.client.get(f'/api-v1/community/groups/{group.id}/resources/').status_code, 404)

    def test_atomic_task_creation_retries_keep_one_goal_pod_and_post(self):
        group = self.make_group()
        task, payload = self.make_task(group)
        retried = self.post('tasks/', payload)
        self.assertEqual(retried['id'], task.id)
        self.assertEqual(task.memberships.filter(state='active').count(), 1)
        self.assertEqual(CommunityTask.objects.count(), 1)
        self.assertEqual(Conversation.objects.filter(goal=task.goal).count(), 1)
        self.assertEqual(Message.objects.filter(conversation=group.conversation, metadata__community_task_id=task.id).count(), 1)

    def test_public_task_capacity_includes_owner(self):
        group = self.make_group()
        self.join_member(group)
        task, _ = self.make_task(group, member_limit=2)
        self.login(self.member)
        self.post(f'tasks/{task.id}/join/')
        self.login(self.admin)
        self.post(f'tasks/{task.id}/join/', expected=400)
        self.assertEqual(task.memberships.filter(state='active').count(), 2)

    def test_private_task_request_has_no_goal_access_before_approval(self):
        group = self.make_group()
        self.join_member(group)
        task, _ = self.make_task(group, visibility='private')
        self.login(self.member)
        self.assertEqual(self.post(f'tasks/{task.id}/join/')['membership']['state'], 'pending')
        self.assertFalse(can_access_goal(task.goal, self.member))
        self.assertEqual(self.client.get(f'/api-v1/goals/{task.goal_id}/').status_code, 404)
        self.login(self.founder)
        self.post(f'tasks/{task.id}/requests/', {'user_id': self.member.id, 'decision': 'approve'})
        self.assertTrue(can_access_goal(task.goal, self.member))

    def test_outside_invitation_requires_acceptance_and_never_joins_group(self):
        group = self.make_group()
        task, _ = self.make_task(group)
        self.post(f'tasks/{task.id}/invitations/', {'user_ids': [self.other.id]})
        self.assertFalse(can_access_goal(task.goal, self.other))
        self.login(self.other)
        self.post(f'tasks/{task.id}/respond/', {'decision': 'accept'})
        self.assertTrue(can_access_goal(task.goal, self.other))
        self.assertFalse(group.memberships.filter(user=self.other).exists())
        self.assertFalse(can_read_group(group, self.other))

    def test_noninternal_limits_and_internal_override_audit(self):
        group = self.make_group()
        self.join_member(group)
        task, payload = self.make_task(group)
        payload.update(idempotency_key='too-big', member_limit=9)
        self.login(self.member)
        self.post('tasks/', payload, 400)
        self.post(f'tasks/{task.id}/limits/', {'member_limit': 9, 'reason': 'Exception'}, 403)
        self.login(self.founder)
        self.post(f'tasks/{task.id}/limits/', {'member_limit': 9, 'reason': 'Approved supervised cohort'})
        task.refresh_from_db()
        self.assertEqual(task.member_limit, 9)
        self.assertEqual(task.limits_approved_by, self.founder)
        self.assertTrue(CommunityAudit.objects.filter(action='task.limits_approved', actor=self.founder).exists())

    def test_group_delete_preserves_pod_task_delete_archives(self):
        group = self.make_group()
        task, _ = self.make_task(group)
        self.post(f'groups/{group.id}/lifecycle/', {'status': 'deleted', 'reason': 'Retired community'})
        group.refresh_from_db()
        self.assertFalse(can_post_group(group, self.admin))
        self.assertTrue(can_read_group(group, self.admin))
        task.refresh_from_db()
        self.assertTrue(can_write_goal(task.goal, self.founder))
        self.post(f'tasks/{task.id}/lifecycle/', {'status': 'deleted', 'reason': 'Task ended'})
        task.refresh_from_db()
        self.assertEqual(task.status, 'archived')
        self.assertTrue(can_access_goal(task.goal, self.founder))
        self.assertFalse(can_write_goal(task.goal, self.founder))
        self.assertEqual(generate_task_cycles(task), 0)

    def test_owner_must_transfer_before_leaving(self):
        group = self.make_group()
        self.join_member(group)
        task, _ = self.make_task(group)
        self.login(self.member)
        self.post(f'tasks/{task.id}/join/')
        self.login(self.founder)
        self.post(f'tasks/{task.id}/leave/', {'reason': 'Done'}, 400)
        self.post(f'tasks/{task.id}/leave/', {'reason': 'Done', 'transfer_to': self.member.id})
        task.goal.refresh_from_db()
        self.assertEqual(task.goal.user_id, self.member.id)
        self.assertTrue(can_write_goal(task.goal, self.founder))  # Internal recovery remains available.
        self.assertEqual(task.memberships.get(user=self.member).role, 'admin')

    def test_cycles_deduplicate_and_progress_is_latest_overall_average(self):
        group = self.make_group()
        self.join_member(group)
        task, _ = self.make_task(group)
        self.login(self.member)
        self.post(f'tasks/{task.id}/join/')
        self.login(self.founder)
        generate_task_cycles(task)
        count = task.goal.checkins.count()
        generate_task_cycles(task)
        self.assertEqual(task.goal.checkins.count(), count)
        today = timezone.localdate()
        GoalCheckin.objects.filter(goal=task.goal, user=self.founder, scheduled_for=today).update(completion_percent=80, submitted_at=timezone.now())
        GoalCheckin.objects.filter(goal=task.goal, user=self.member, scheduled_for=today).update(completion_percent=20, submitted_at=timezone.now())
        result = self.client.get(f'/api-v1/community/tasks/{task.id}/').data
        self.assertEqual(result['progress'], 50)
        self.assertEqual(result['milestone_completion']['completed'], 0)

    def test_28_day_inactivity_flags_notifies_and_does_not_remove(self):
        group = self.make_group()
        self.join_member(group)
        old = timezone.now() - timedelta(days=29)
        get_user_model().objects.filter(pk=self.member.id).update(last_login=old)
        self.assertEqual(review_inactive_members(), 1)
        self.assertEqual(review_inactive_members(), 0)
        self.assertTrue(CommunityInactivityReview.objects.filter(user=self.member, group=group).exists())
        self.assertTrue(group.memberships.filter(user=self.member, state='active').exists())
        self.assertTrue(Notification.objects.filter(user=self.founder, type='community_inactivity_review').exists())

    def test_member_cannot_change_roles_or_access_internal_user_picker(self):
        group = self.make_group()
        self.join_member(group)
        self.login(self.member)
        self.post(f'groups/{group.id}/members/', {'user_id': self.member.id, 'action': 'role', 'role': 'admin'}, 403)
        self.assertEqual(self.client.get('/api-v1/community/users/').status_code, 403)
        self.assertEqual(self.client.get('/api-v1/community/hq/users/').status_code, 404)

    def test_group_permissions_require_real_booleans(self):
        group = self.make_group()
        response = self.client.patch(f'/api-v1/community/groups/{group.id}/', {'post_permissions': {'image': 'false'}}, format='json')
        self.assertEqual(response.status_code, 400)
        response = self.client.patch(f'/api-v1/community/groups/{group.id}/', {'post_permissions': {'image': False}}, format='json')
        self.assertEqual(response.status_code, 200)
        group.refresh_from_db()
        self.assertFalse(can_post_group(group, self.admin, 'image'))
        self.assertTrue(can_post_group(group, self.admin, 'text'))

    def test_platform_ban_denies_every_access_helper(self):
        group = self.make_group()
        self.join_member(group)
        task, _ = self.make_task(group)
        self.login(self.member)
        self.post(f'tasks/{task.id}/join/')
        self.login(self.founder)
        self.post('hq/moderate-user/', {'user_id': self.member.id, 'action': 'ban', 'reason': 'Platform rule violation'})
        self.member.refresh_from_db()
        self.assertFalse(can_read_group(group, self.member))
        self.assertFalse(can_access_goal(task.goal, self.member))
        self.assertFalse(visible_messages(Message.objects.all(), self.member).exists())

    def test_profile_message_opens_real_dm_and_reuses_without_buddy(self):
        group = self.make_group()
        self.join_member(group)
        self.login(self.member)
        first = self.post(f'users/{self.admin.id}/message/', {'group_id': group.id})
        second = self.post(f'users/{self.admin.id}/message/', {'group_id': group.id})
        self.assertEqual(first['conversation_id'], second['conversation_id'])
        conversation = Conversation.objects.get(pk=first['conversation_id'])
        self.assertFalse(conversation.is_group)
        self.assertIsNone(conversation.partnership_id)
        self.assertEqual(set(conversation.members.values_list('id', flat=True)), {self.member.id, self.admin.id})
        self.post(f'users/{self.other.id}/message/', {'group_id': group.id}, 403)
        UserBlock.objects.create(blocker=self.admin, blocked=self.member)
        self.post(f'users/{self.admin.id}/message/', {'group_id': group.id}, 403)

    def test_outside_pod_member_can_message_pod_peer_not_source_group(self):
        group = self.make_group()
        task, _ = self.make_task(group)
        self.post(f'tasks/{task.id}/invitations/', {'user_ids': [self.other.id]})
        self.login(self.other)
        self.post(f'tasks/{task.id}/respond/', {'decision': 'accept'})
        self.post(f'users/{self.founder.id}/message/', {'group_id': group.id}, 403)
        dm = self.post(f'users/{self.founder.id}/message/', {'goal_id': task.goal_id})
        self.assertTrue(Conversation.objects.filter(pk=dm['conversation_id'], members=self.other).exists())

    def test_public_pod_link_requires_approval_and_cannot_bypass_through_join(self):
        group = self.make_group()
        self.join_member(group)
        task, _ = self.make_task(group)
        link = self.post(f'tasks/{task.id}/invite-link/')
        self.assertTrue(link['approval_required'])
        self.assertIn('/community?pod_invite=', link['url'])
        self.login(self.member)
        requested = self.post('tasks/join-link/', {'token': link['token']})
        self.assertEqual(requested['state'], 'pending')
        self.assertFalse(can_access_goal(task.goal, self.member))
        result = self.post(f'tasks/{task.id}/join/')
        self.assertEqual(result['membership']['state'], 'pending')
        self.login(self.founder)
        self.post(f'tasks/{task.id}/requests/', {'user_id': self.member.id, 'decision': 'approve'})
        self.assertTrue(can_access_goal(task.goal, self.member))

    def test_outside_link_requests_can_be_reviewed_without_source_access(self):
        group = self.make_group()
        task, _ = self.make_task(group, member_limit=1)
        self.post(f'tasks/{task.id}/invite-link/', expected=400)
        self.post(f'tasks/{task.id}/limits/', {'member_limit': 2, 'reason': 'Open second place'})
        link = self.post(f'tasks/{task.id}/invite-link/')
        self.login(self.other)
        self.assertEqual(self.post('tasks/join-link/', {'token': link['token']})['state'], 'pending')
        self.assertFalse(can_read_group(group, self.other))
        self.assertEqual(self.client.get(f'/api-v1/community/tasks/{task.id}/').status_code, 200)
        self.assertEqual(self.client.get(f'/api-v1/goals/{task.goal_id}/').status_code, 404)
        self.login(self.founder)
        self.post(f'tasks/{task.id}/requests/', {'user_id': self.other.id, 'decision': 'approve'})
        self.assertTrue(can_access_goal(task.goal, self.other))
        self.assertFalse(group.memberships.filter(user=self.other).exists())

    def test_task_settings_change_domain_visibility_and_deny_member(self):
        group = self.make_group()
        self.join_member(group)
        task, _ = self.make_task(group)
        payload = {'title': 'New sprint name', 'description': 'Updated focus', 'visibility': 'private', 'checkin_frequency': 'CUSTOM', 'custom_interval_days': 3}
        response = self.client.patch(f'/api-v1/community/tasks/{task.id}/', payload, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        task.refresh_from_db()
        task.goal.refresh_from_db()
        self.assertEqual(task.visibility, 'private')
        self.assertFalse(task.goal.is_public)
        self.assertEqual(task.goal.title, payload['title'])
        self.assertEqual(task.goal.checkin_frequency, 'CUSTOM')
        self.assertTrue(CommunityAudit.objects.filter(task=task, action='task.settings_changed').exists())
        self.login(self.member)
        self.assertEqual(self.client.patch(f'/api-v1/community/tasks/{task.id}/', {'title': 'No'}, format='json').status_code, 403)

    def test_hq_inventory_filters_and_complete_paginated_picker(self):
        group = self.make_group()
        self.post(f'groups/{group.id}/report/', {'reason': 'Review needed'}, 201)
        url = '/api-v1/community/hq/groups/?min_members=2&min_reports=1&ordering=-activity'
        data = self.client.get(url).data
        self.assertEqual(data['count'], 1)
        self.assertEqual(data['results'][0]['report_count'], 1)
        self.assertEqual(self.client.get('/api-v1/community/hq/groups/?min_members=3').data['count'], 0)
        self.assertEqual(self.client.get('/api-v1/community/hq/groups/?created_after=2999-01-01').data['count'], 0)
        get_user_model().objects.bulk_create([get_user_model()(name=f'Picker {i}', email=f'picker{i}@test.example') for i in range(55)])
        data = self.client.get('/api-v1/community/users/?search=Picker&page_size=30').data
        self.assertEqual(data['count'], 55)
        self.assertEqual(len(data['results']), 30)
        self.assertIsNotNone(data['next'])
        self.assertEqual(len(self.client.get(data['next']).data['results']), 25)

    def test_group_admin_explicit_inactivity_review_retains_or_removes(self):
        group = self.make_group()
        self.join_member(group)
        get_user_model().objects.filter(pk=self.member.id).update(last_login=timezone.now() - timedelta(days=29))
        review_inactive_members()
        self.login(self.admin)
        data = self.client.get(f'/api-v1/community/groups/{group.id}/inactivity-reviews/').data
        review = data['results'][0]
        self.assertEqual(review['user']['id'], self.member.id)
        self.post(f'groups/{group.id}/inactivity-reviews/', {'review_id': review['id'], 'decision': 'remove', 'reason': 'Membership reviewed; remove'})
        self.assertTrue(group.memberships.filter(user=self.member, state='removed').exists())
        self.assertTrue(CommunityInactivityReview.objects.get(pk=review['id']).resolved)

    def test_hq_evidence_is_paginated_internal_only_and_community_scoped(self):
        group = self.make_group()
        task, _ = self.make_task(group)
        today = timezone.now().date()
        ids = []
        for day in range(3):
            checkin, _ = GoalCheckin.objects.get_or_create(
                goal=task.goal, user=self.founder, scheduled_for=today + timedelta(days=day),
            )
            GoalCheckin.objects.filter(pk=checkin.pk).update(
                evidence=f'checkin_evidence/{day}.png', submitted_at=timezone.now(),
            )
            ids.append(checkin.id)
        GoalCheckin.objects.create(goal=task.goal, user=self.founder, scheduled_for=today + timedelta(days=4))
        legacy = Goal.objects.create(user=self.founder, title='Legacy private goal')
        GoalCheckin.objects.create(goal=legacy, user=self.founder, scheduled_for=today, evidence='legacy.png')
        first = self.client.get('/api-v1/community/hq/evidence/?page_size=2')
        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.data['count'], 3)
        self.assertEqual(len(first.data['results']), 2)
        second = self.client.get(first.data['next'])
        results = first.data['results'] + second.data['results']
        self.assertEqual({row['id'] for row in results}, set(ids))
        self.assertTrue(all(row['user']['id'] == self.founder.id for row in results))
        self.assertTrue(all('/evidence/' in row['evidence_url'] for row in results))
        self.assertIsNone(second.data['next'])
        self.login(self.admin)
        self.assertEqual(self.client.get('/api-v1/community/hq/evidence/').status_code, 404)

    def test_hq_users_include_explicit_creator_approval(self):
        self.post('hq/approve-creator/', {'user_id': self.member.id, 'approved': True})
        approved = self.client.get('/api-v1/community/hq/users/?search=Member').data['results']
        flags = {row['id']: row['group_creation_approved'] for row in approved}
        self.assertTrue(flags[self.member.id])
        self.assertFalse(flags[self.other.id])
        self.post('hq/approve-creator/', {'user_id': self.member.id, 'approved': False})
        flags = {row['id']: row['group_creation_approved'] for row in self.client.get('/api-v1/community/hq/users/?search=Member').data['results']}
        self.assertFalse(flags[self.member.id])

    def test_profile_message_supports_legacy_pods_and_consistent_dual_ids(self):
        goal = Goal.objects.create(user=self.member, title='Legacy shared goal', is_shared=True)
        GoalMembership.objects.get_or_create(goal=goal, user=self.other)
        self.login(self.member)
        dm = self.post(f'users/{self.other.id}/message/', {'goal_id': goal.id})
        self.assertTrue(Conversation.objects.filter(pk=dm['conversation_id']).exists())
        self.login(self.founder)
        group = self.make_group()
        task, _ = self.make_task(group)
        self.post(f'tasks/{task.id}/invitations/', {'user_ids': [self.other.id]})
        self.login(self.other)
        self.post(f'tasks/{task.id}/respond/', {'decision': 'accept'})
        self.post(f'users/{self.founder.id}/message/', {'goal_id': task.goal_id, 'task_id': task.id})
        self.post(f'users/{self.founder.id}/message/', {'goal_id': goal.id, 'task_id': task.id}, 400)

    def test_cadence_changes_preserve_issued_cycles_without_retroactive_misses(self):
        group = self.make_group()
        today = timezone.localdate()
        for frequency, interval, update in [('WEEKLY', None, {'checkin_frequency': 'DAILY'}),
                                             ('CUSTOM', 3, {'custom_interval_days': 2})]:
            with self.subTest(frequency=frequency):
                task, _ = self.make_task(group, checkin_frequency=frequency, custom_interval_days=interval,
                                         idempotency_key='cadence-' + frequency)
                task.goal.start_date = today - timedelta(days=7)
                task.goal.save(update_fields=['start_date'])
                task.memberships.update(joined_at=timezone.now() - timedelta(days=8))
                generate_task_cycles(task)
                issued = set(task.goal.checkins.filter(scheduled_for__lte=today).values_list('id', 'scheduled_for'))
                current = task.goal.checkins.get(user=self.founder, scheduled_for=today)
                response = self.client.patch(f'/api-v1/community/tasks/{task.id}/', update, format='json')
                self.assertEqual(response.status_code, 200, response.data)
                task.refresh_from_db()
                self.assertEqual(task.checkin_schedule_effective_from, today + timedelta(days=1))
                self.assertTrue(task.goal.checkins.filter(pk=current.pk).exists())
                for days_later in (0, 1, 4):
                    generate_task_cycles(task, timezone.now() + timedelta(days=days_later))
                    actual = set(task.goal.checkins.filter(scheduled_for__lte=today).values_list('id', 'scheduled_for'))
                    self.assertEqual(actual, issued)
                future = task.goal.checkins.filter(scheduled_for__gt=today).first()
                self.assertIsNotNone(future)
                response = self.client.patch(f'/api-v1/community/tasks/{task.id}/', update, format='json')
                self.assertEqual(response.status_code, 200, response.data)
                self.assertTrue(task.goal.checkins.filter(pk=future.pk).exists())

    def test_task_rename_does_not_rewrite_source_history_or_reports(self):
        group = self.make_group()
        self.login(self.admin)
        task, _ = self.make_task(group)
        card = group.conversation.messages.get(metadata__community_task_id=task.id)
        before = (card.text, card.updated_at)
        ContentReport.objects.create(reporter=self.founder, message=card, conversation=group.conversation, reason='other')
        for status in ('active', 'frozen', 'deleted'):
            group.status = status
            group.save(update_fields=['status'])
            with patch('api.community_messaging.broadcast_message') as broadcast:
                response = self.client.patch(f'/api-v1/community/tasks/{task.id}/', {'title': 'Renamed ' + status}, format='json')
                self.assertEqual(response.status_code, 200, response.data)
                self.assertFalse(any(call.args and call.args[0] == card.id for call in broadcast.call_args_list))
            card.refresh_from_db()
            self.assertEqual((card.text, card.updated_at), before)
        group.status = 'active'
        group.save(update_fields=['status'])
        self.login(self.founder)
        self.post(f'groups/{group.id}/members/', {'user_id': self.admin.id, 'action': 'remove', 'reason': 'Group-only removal'})
        self.login(self.admin)
        response = self.client.patch(f'/api-v1/community/tasks/{task.id}/', {'title': 'Independent pod'}, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        card.refresh_from_db()
        self.assertEqual((card.text, card.updated_at), before)
        task.goal.refresh_from_db()
        self.assertEqual(task.goal.title, 'Independent pod')
        self.assertEqual(task.goal.conversation.name, 'Independent pod')

    def test_inactive_members_are_admin_removable_and_pod_capacity_recovers(self):
        group = self.make_group()
        self.join_member(group)
        task, _ = self.make_task(group, member_limit=2)
        self.login(self.member)
        self.post(f'tasks/{task.id}/join/')
        self.member.is_active = False
        self.member.save(update_fields=['is_active'])
        self.login(self.founder)
        task_data = self.client.get(f'/api-v1/community/tasks/{task.id}/').data
        self.assertEqual(task_data['member_count'], 2)
        self.assertEqual(task_data['enrollment_status'], 'full')
        self.post(f'groups/{group.id}/members/', {'user_id': self.member.id, 'action': 'remove', 'reason': 'Reviewed disabled member'})
        response = self.client.delete(f'/api-v1/goals/{task.goal_id}/members/{self.member.id}/', {'reason': 'Reviewed pod membership'}, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        membership = task.memberships.get(user=self.member)
        self.assertEqual(membership.state, 'removed')
        self.assertFalse(membership.periods.filter(ended_at__isnull=True).exists())
        self.assertFalse(GoalMembership.objects.filter(goal=task.goal, user=self.member).exists())
        self.assertFalse(ConversationMembership.objects.filter(conversation=task.goal.conversation, user=self.member).exists())
        self.assertEqual(self.client.get(f'/api-v1/community/tasks/{task.id}/').data['enrollment_status'], 'open')
        self.member.is_active = True
        self.member.save(update_fields=['is_active'])
        self.assertFalse(can_access_goal(task.goal, self.member))
        self.assertFalse(can_read_group(group, self.member))

    def test_inactive_second_admin_removal_does_not_reduce_active_admin_count(self):
        group = self.make_group()
        self.admin.is_active = False
        self.admin.save(update_fields=['is_active'])
        self.post(f'groups/{group.id}/members/', {'user_id': self.admin.id, 'action': 'remove', 'reason': 'Remove unavailable admin'})
        self.assertEqual(group.memberships.get(user=self.admin).state, 'removed')
        self.assertEqual(group.memberships.filter(user=self.founder, state='active', role='admin').count(), 1)
        self.post(f'groups/{group.id}/members/', {'user_id': self.admin.id, 'action': 'invite'}, 400)

    def test_banned_members_filter_is_scoped_and_restricted_to_moderators(self):
        group = self.make_group()
        self.join_member(group)
        self.join_member(group, self.other)
        self.post(f'groups/{group.id}/members/', {'user_id': self.member.id, 'action': 'ban', 'reason': 'Group misconduct'})
        self.login(self.admin)
        data = self.client.get(f'/api-v1/community/groups/{group.id}/members/?state=banned').data
        self.assertEqual([row['user']['id'] for row in data], [self.member.id])
        self.assertTrue(all(row['state'] == 'banned' for row in data))
        self.login(self.other)
        self.assertEqual(self.client.get(f'/api-v1/community/groups/{group.id}/members/?state=banned').status_code, 403)
        data = self.client.get(f'/api-v1/community/groups/{group.id}/members/').data
        self.assertNotIn(self.member.id, [row['user']['id'] for row in data])

    def test_group_report_queue_review_and_evidence_are_group_scoped(self):
        group = self.make_group()
        self.join_member(group)
        self.join_member(group, self.other)
        self.post(f'groups/{group.id}/members/', {'user_id': self.member.id, 'action': 'role', 'role': 'moderator'})
        other_group = self.make_group()
        reply = Message.objects.create(conversation=group.conversation, sender=self.founder, text='Context')
        message = Message.objects.create(conversation=group.conversation, sender=self.other, text='Reported content', reply_to_message=reply)
        original = ContentReport.objects.create(reporter=self.admin, reported_user=self.other, message=message,
                                                conversation=group.conversation, reason='other', details='Review this')
        other_report = CommunityReport.objects.create(group=other_group, reporter=self.founder, reason='Other group')
        self.login(self.member)
        queue = self.client.get(f'/api-v1/community/groups/{group.id}/reports/?status=pending&page_size=1')
        self.assertEqual(queue.status_code, 200, queue.data)
        self.assertEqual(queue.data['count'], 1)
        report = queue.data['results'][0]
        self.assertEqual(report['content_report_id'], original.id)
        self.assertEqual(report['allowed_actions'], ['remove_message'])
        evidence = self.client.get(report['evidence_url'])
        self.assertEqual(evidence.status_code, 200, evidence.data)
        self.assertEqual(evidence.data['text'], message.text)
        self.assertIsNone(evidence.data['reply_to'])
        self.post(f'groups/{group.id}/review-report/', {'report_id': other_report.id, 'status': 'dismissed'}, 404)
        self.post(f'groups/{group.id}/review-report/', {'report_id': report['id'], 'status': 'actioned', 'action': 'ban_user', 'reason': 'No platform authority'}, 400)
        self.post(f'groups/{group.id}/review-report/', {'report_id': report['id'], 'status': 'reviewed', 'notes': 'Remove group content', 'action': 'remove_message'})
        original.refresh_from_db()
        self.assertEqual(original.status, 'reviewed')
        evidence = self.client.get(report['evidence_url'])
        self.assertEqual(evidence.status_code, 200, evidence.data)
        self.assertEqual(evidence.data['text'], 'This message was removed by a moderator')
        self.assertIsNone(evidence.data['attachment'])
        self.login(self.other)
        self.assertEqual(self.client.get(f'/api-v1/community/groups/{group.id}/reports/').status_code, 403)
        self.assertEqual(self.client.get(report['evidence_url']).status_code, 403)
        self.post(f'groups/{group.id}/review-report/', {'report_id': report['id'], 'status': 'dismissed'}, 403)

    def test_media_only_can_post_capability_does_not_authorize_text(self):
        group = self.make_group()
        self.join_member(group)
        group.post_permissions = {kind: kind == 'image' for kind in group.post_permissions}
        group.save(update_fields=['post_permissions'])
        self.login(self.member)
        self.assertTrue(self.client.get(f'/api-v1/community/groups/{group.id}/').data['can_post'])
        self.post('messages/', {'conversation': group.conversation_id, 'text': 'Not allowed'}, 403)
        with tempfile.TemporaryDirectory() as media, override_settings(PRIVATE_MEDIA_ROOT=media):
            image = SimpleUploadedFile('photo.png', b'image', content_type='image/png')
            response = self.client.post('/api-v1/community/messages/', {'conversation': group.conversation_id, 'attachment': image}, format='multipart')
            self.assertEqual(response.status_code, 201, response.data)
        group.post_permissions['image'] = False
        group.save(update_fields=['post_permissions'])
        self.assertFalse(self.client.get(f'/api-v1/community/groups/{group.id}/').data['can_post'])

    def test_community_people_show_only_existing_earned_achievements_without_mutation(self):
        from .awards import AWARD_BY_KEY
        group = self.make_group()
        self.join_member(group)
        task, _ = self.make_task(group)
        self.login(self.member)
        self.post(f'tasks/{task.id}/join/')
        award, _ = UserAward.objects.get_or_create(user=self.member, award_key='goal_started')
        UserAward.objects.get_or_create(user=self.member, award_key='unknown_future_award')
        expected = [{'id': earned.id, 'key': earned.award_key, 'name': AWARD_BY_KEY[earned.award_key].title}
                    for earned in self.member.awards.all() if earned.award_key in AWARD_BY_KEY]
        self.assertIn({'id': award.id, 'key': 'goal_started', 'name': AWARD_BY_KEY['goal_started'].title}, expected)
        before = list(UserAward.objects.order_by('id').values())
        notification_count = Notification.objects.count()
        with patch('api.awards.award_progress_for_user', side_effect=AssertionError('Read must not calculate awards')):
            group_members = self.client.get(f'/api-v1/community/groups/{group.id}/members/').data
            task_members = self.client.get(f'/api-v1/community/tasks/{task.id}/').data['members']
        for members in (group_members, task_members):
            person = next(member['user'] for member in members if member['user']['id'] == self.member.id)
            self.assertEqual(person['achievements'], expected)
        self.assertEqual(list(UserAward.objects.order_by('id').values()), before)
        self.assertEqual(Notification.objects.count(), notification_count)

    def test_task_multipart_cover_and_json_collections_match_frontend_contract(self):
        group = self.make_group()
        task, payload = self.make_task(group)
        payload['idempotency_key'] = 'multipart-task'
        payload['milestones'] = json.dumps(payload['milestones'])
        payload['invited_user_ids'] = json.dumps([self.other.id])
        payload['cover'] = SimpleUploadedFile('cover.png', b'test-cover-image', content_type='image/png')
        with tempfile.TemporaryDirectory() as media, override_settings(PRIVATE_MEDIA_ROOT=media):
            response = self.client.post('/api-v1/community/tasks/', payload, format='multipart')
            self.assertEqual(response.status_code, 201, response.data)
            created = CommunityTask.objects.get(pk=response.data['id'])
            self.assertEqual(created.goal.tasks.count(), 1)
            self.assertTrue(created.invitations.filter(user=self.other, status='pending').exists())
            cover = self.client.get(f'/api-v1/community/tasks/{created.id}/cover/')
            self.assertEqual(cover.status_code, 200)
            cover.close()
            self.login(self.other)
            self.post(f'tasks/{created.id}/respond/', {'decision': 'decline'})
            self.assertEqual(self.client.get(f'/api-v1/community/tasks/{created.id}/cover/').status_code, 404)
