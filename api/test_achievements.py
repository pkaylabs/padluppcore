"""Community catalog, source attribution, historical facts and claim regressions."""
from datetime import datetime, time, timedelta, timezone as dt_timezone
from importlib import import_module
from unittest.mock import patch

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import SimpleTestCase, override_settings
from django.utils import timezone
from rest_framework.test import APITestCase

from .achievements import (
    ACHIEVEMENTS, _owed_dates, evaluate_achievements, is_positive_emoji,
    record_pod_inactivity,
)
from . import achievements
from .community_models import CommunityInactivityReview
from .community_serializers import user_data
from .community_services import (
    generate_task_cycles, invite_task_users, join_task, leave_task,
    review_inactive_members, set_task_status,
)
from .message_models import MessageReaction
from .models import AchievementCredit, GoalCheckin, Message, Notification, Partnership, Task, UserAward
from .test_community_acceptance import CommunityFixtures, TEST_SETTINGS
from .viewsets import _set_last_login


@override_settings(**TEST_SETTINGS)
class AchievementTests(CommunityFixtures, APITestCase):
    def setUp(self):
        super().setUp()
        self.today = timezone.now().astimezone(dt_timezone.utc).date()
        self.now = self.at(self.today, 12)
        for user in (self.owner, self.member, self.other, self.admin):
            user.last_login = self.now
            user.save(update_fields=['last_login'])

    @staticmethod
    def at(day, hour=0):
        return datetime.combine(day, time(hour), tzinfo=dt_timezone.utc)

    def pod(self, *, days=0, target=None, member=None, **fields):
        task = self.task(**fields)
        task.goal.start_date = self.today - timedelta(days=days)
        task.goal.target_date = target or self.today
        task.goal.save(update_fields=['start_date', 'target_date'])
        owner = task.memberships.get(user=self.owner)
        owner.joined_at = self.at(task.goal.start_date)
        owner.save(update_fields=['joined_at'])
        owner.periods.update(joined_at=owner.joined_at)
        if member:
            self.admit_pod(task, member, joined_at=self.at(task.goal.start_date))
        return task

    def checkin(self, task, user=None, due=None, *, at=None, evidence=True, state='partial'):
        user, due = user or self.owner, due or self.today
        row, _ = GoalCheckin.objects.get_or_create(goal=task.goal, user=user, scheduled_for=due)
        row.status = state
        row.submitted_at = at or self.at(due, 10)
        row.evidence = 'checkin_evidence/test.png' if evidence else None
        row.save()
        return row

    def close(self, task, *, at=None, state='completed'):
        with patch('api.community_services.timezone.now', return_value=at or self.now):
            return set_task_status(task, self.owner, state, 'Test lifecycle')

    def catalog(self, user=None):
        self.client.force_authenticate(user or self.owner)
        response = self.client.get('/api-v1/achievements/')
        self.assertEqual(response.status_code, 200, response.data)
        return {row['key']: row for row in response.data['achievements']}

    def credits(self, user=None, kind=None):
        rows = AchievementCredit.objects.filter(user=user or self.owner)
        return rows.filter(kind=kind) if kind else rows

    def test_catalog_contract_order_claim_boundaries_and_account_isolation(self):
        rows = self.catalog()
        self.assertEqual(list(rows), [definition.key for definition in ACHIEVEMENTS])
        self.assertEqual(set(rows['pod_creator']), {
            'key', 'name', 'description', 'current', 'target', 'eligible', 'earned_at', 'claimed_at', 'requirements',
        })
        self.assertEqual(len(rows), 9)
        self.assertEqual(self.client.post('/api-v1/achievements/unknown/claim/').status_code, 404)
        self.assertEqual(self.client.post('/api-v1/achievements/pod_creator/claim/').status_code, 409)
        self.assertEqual(self.client.post('/api-v1/achievements/pod_creator/claim/',
                                         {'current': 10, 'eligible': True}, format='json').status_code, 400)
        for index in range(3):
            self.close(self.pod())
        self.assertTrue(self.catalog()['no_ghosting']['eligible'])
        self.assertFalse(self.catalog(self.member)['no_ghosting']['eligible'])
        self.client.force_authenticate(None)
        self.assertEqual(self.client.get('/api-v1/achievements/').status_code, 401)
        self.client.force_authenticate(self.member)
        self.member.is_active = False
        self.member.save(update_fields=['is_active'])
        self.assertEqual(self.client.get('/api-v1/achievements/').status_code, 403)

    def test_claim_is_idempotent_and_profile_only_collects_claimed_new_awards(self):
        for index in range(3):
            self.close(self.pod())
        item = self.catalog()['no_ghosting']
        self.assertIsNotNone(item['earned_at'])
        self.assertIsNone(item['claimed_at'])
        self.assertFalse(any(row['key'] == 'no_ghosting' for row in user_data(self.owner)['achievements']))
        notifications = Notification.objects.count()
        response = self.client.post('/api-v1/achievements/no_ghosting/claim/')
        self.assertEqual(response.status_code, 200, response.data)
        self.assertIsNotNone(response.data['claimed_at'])
        self.assertEqual(response.data['earned_at'], item['earned_at'])
        again = self.client.post('/api-v1/achievements/no_ghosting/claim/')
        self.assertEqual(response.data, again.data)
        self.assertEqual(Notification.objects.count(), notifications)
        profile = user_data(self.owner)['achievements']
        self.assertEqual(len([row for row in profile if row['key'] == 'no_ghosting']), 1)
        self.assertTrue(all(row.get('legacy') is True for row in profile if row['key'] == 'goal_started'))
        self.assertEqual(UserAward.objects.filter(user=self.owner, award_key='no_ghosting').count(), 1)

    def test_legacy_catalog_keys_and_grants_are_unchanged(self):
        legacy = list(UserAward.objects.filter(user=self.owner).values('id', 'award_key', 'unlocked_at', 'progress_snapshot'))
        catalog = self.catalog()
        response = self.client.get('/api-v1/awards/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['total_count'], 9)
        keys = {item['key'] for category in response.data['categories'] for item in category['awards']}
        self.assertTrue(keys.isdisjoint(catalog))
        for original in legacy:
            self.assertEqual(UserAward.objects.filter(pk=original['id']).values(*original).get(), original)

    def test_enrollment_hooks_count_accepted_others_and_capacity_creator_slot(self):
        for index in range(3):
            task = self.pod(member_limit=4)
            with patch('api.community_services.timezone.now', return_value=self.now):
                invite_task_users(task, self.owner, [self.member.pk, self.other.pk])
                self.assertEqual(self.credits(kind='pod_created_joined').count(), index)
                join_task(task, self.member, invited=True)
                self.assertEqual(self.credits(kind='pod_capacity').count(), index)
                join_task(task, self.other, invited=True)
        self.assertTrue(self.catalog()['pod_magnet']['eligible'])
        self.assertEqual(self.catalog()['pod_creator']['current'], 3)
        credit = self.credits(kind='pod_capacity').first()
        self.assertEqual((credit.metadata['member_count'], credit.metadata['member_limit']), (3, 4))
        with patch('api.community_services.timezone.now', return_value=self.now):
            leave_task(task, self.other, 'Leaving')
            join_task(task, self.other)
        self.assertEqual(self.credits(kind='pod_capacity').count(), 3)

    def test_historical_creator_and_current_capacity_reconcile_once_without_hooks(self):
        for index in range(10):
            task = self.pod(member=self.member, member_limit=2)
        with patch('api.achievements.evaluate_achievements', wraps=evaluate_achievements) as evaluate:
            rows = self.catalog()
        self.assertEqual(evaluate.call_count, 1)
        self.assertTrue(rows['pod_creator']['eligible'])
        self.assertTrue(rows['pod_magnet']['eligible'])
        count = self.credits().count()
        self.catalog()
        self.assertEqual(self.credits().count(), count)
        self.assertEqual(UserAward.objects.filter(user=self.owner, award_key='pod_creator').count(), 1)

    def test_first_claim_reconciles_history_without_catalog_get(self):
        for index in range(10):
            self.pod(member=self.member)
        self.client.force_authenticate(self.owner)
        response = self.client.post('/api-v1/achievements/pod_creator/claim/')
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data['current'], 10)
        self.assertIsNotNone(response.data['claimed_at'])
        self.assertEqual(self.client.post('/api-v1/achievements/goal_started/claim/').status_code, 404)

    def test_evidence_backfill_requires_evidence_and_authorized_submission_period(self):
        task = self.pod(days=12)
        for index in range(10):
            self.checkin(task, due=self.today - timedelta(days=index))
        self.checkin(task, due=self.today - timedelta(days=10), evidence=False)
        self.checkin(task, due=self.today - timedelta(days=20))
        row = self.catalog()['proof_in_the_pudding']
        self.assertTrue(row['eligible'])
        self.assertEqual(self.credits(kind='checkin_submitted').count(), 10)
        self.assertTrue(all(credit.metadata['evidence_backed'] for credit in self.credits(kind='checkin_submitted')))
        checkin = task.goal.checkins.get(scheduled_for=self.today)
        checkin.evidence = None
        checkin.save(update_fields=['evidence'])
        self.assertEqual(self.catalog()['proof_in_the_pudding']['current'], 10)
        self.assertNotIn('update_text', self.credits(kind='checkin_submitted').first().metadata)

    def test_submission_api_records_evidence_fact_once(self):
        task = self.pod()
        with patch('api.community_services.timezone.now', return_value=self.now):
            generate_task_cycles(task)
        self.client.force_authenticate(self.owner)
        with patch('api.viewsets.timezone.now', return_value=self.now):
            response = self.client.post('/api-v1/checkins/', {
                'goal': task.goal_id, 'scheduled_for': self.today.isoformat(), 'status': 'blocked',
                'completion_percent': 0, 'blocker': 'Waiting', 'mood': 'Hopeful',
                'update_text': 'An honest update', 'next_focus': 'Try again',
                'evidence': SimpleUploadedFile('proof.txt', b'proof', content_type='text/plain'),
            }, format='multipart')
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(self.credits(kind='checkin_submitted').count(), 1)
        self.assertEqual(self.catalog()['proof_in_the_pudding']['current'], 1)

    def test_confirmations_need_two_pods_preserve_original_actor_after_overwrite(self):
        task = self.pod(days=10, member=self.member)
        self.admit_pod(task, self.other, joined_at=self.at(task.goal.start_date))
        self.client.force_authenticate(self.member)
        for index in range(10):
            checkin = self.checkin(task, due=self.today - timedelta(days=index))
            response = self.client.post(f'/api-v1/checkins/{checkin.pk}/review/', {'approved': True}, format='json')
            self.assertEqual(response.status_code, 200, response.data)
        rows = self.catalog(self.member)
        self.assertEqual(rows['accountability_ace']['current'], 10)
        self.assertFalse(rows['accountability_ace']['eligible'])
        self.client.force_authenticate(self.other)
        self.client.post(f'/api-v1/checkins/{checkin.pk}/review/', {'approved': False}, format='json')
        self.assertEqual(self.credits(self.member, 'checkin_confirmed').count(), 10)
        other_task = self.pod(member=self.member)
        checkin = self.checkin(other_task)
        self.client.force_authenticate(self.member)
        self.assertEqual(self.client.post(f'/api-v1/checkins/{checkin.pk}/review/', {'approved': True}, format='json').status_code, 200)
        self.assertTrue(self.catalog(self.member)['accountability_ace']['eligible'])
        self.client.post(f'/api-v1/checkins/{checkin.pk}/review/', {'approved': True}, format='json')
        self.assertEqual(self.credits(self.member, 'checkin_confirmed').count(), 11)

    def test_current_confirmation_and_positive_message_rows_backfill_factual_history(self):
        task = self.pod(member=self.member)
        row = self.checkin(task)
        row.reviewer, row.reviewed_at, row.review_status = self.member, timezone.now(), 'confirmed'
        row.save(update_fields=['reviewer', 'reviewed_at', 'review_status'])
        message = self.message()
        MessageReaction.objects.create(message=message, user=self.member, emoji='\U0001f44d\U0001f3fd')
        # A reaction made before any membership is not an authorized historical fact.
        invalid = self.message(text='Invalid reaction')
        reaction = MessageReaction.objects.create(message=invalid, user=self.member, emoji='\u2764\ufe0f')
        MessageReaction.objects.filter(pk=reaction.pk).update(created_at=self.at(self.today - timedelta(days=40)))
        rows = self.catalog(self.member)
        self.assertEqual(rows['accountability_ace']['current'], 1)
        self.assertEqual(rows['hype_paddie']['current'], 2)
        before = self.credits(self.member).count()
        self.catalog(self.member)
        self.assertEqual(self.credits(self.member).count(), before)

    def test_positive_emoji_exact_normalization_and_negative_sequences(self):
        for emoji in ('\U0001f44d', '\U0001f44d\U0001f3ff', '\u2764\ufe0f', '\U0001f44f\U0001f3fb', '\U0001f389', '\U0001f525'):
            self.assertTrue(is_positive_emoji(emoji), emoji)
        for emoji in ('\U0001f44e', '\U0001f494', 'no\U0001f44d', '\U0001f44d\U0001f44e', '\u2764\ufe0f\u200d\U0001f525', 'like'):
            self.assertFalse(is_positive_emoji(emoji), emoji)

    def test_reactions_toggle_and_confirmations_share_one_checkin_subject(self):
        task = self.pod(member=self.member)
        checkin = self.checkin(task)
        message = self.message(conversation=task.goal.conversation, kind='checkin', metadata={'checkin_id': checkin.pk})
        self.client.force_authenticate(self.member)
        for emoji in ('\U0001f44d', '\U0001f44d', '\U0001f44d', '\U0001f525'):
            response = self.client.post(f'/api-v1/community/messages/{message.pk}/react/', {'emoji': emoji}, format='json')
            self.assertEqual(response.status_code, 200, response.data)
        response = self.client.post(f'/api-v1/checkins/{checkin.pk}/review/', {'approved': True}, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(self.catalog(self.member)['hype_paddie']['current'], 1)
        self.assertEqual(self.credits(self.member, 'positive_interaction').get().subject_type, 'checkin')

    def test_hype_combines_given_reactions_and_confirmations_across_five_others(self):
        task = self.pod(days=4, member=self.member)
        authors = [self.owner, self.other, self.admin]
        for index in range(2):
            author = self.user(f'hype-{index}')
            self.admit(author)
            authors.append(author)
        for author in authors[1:]:
            self.admit_pod(task, author, joined_at=self.at(task.goal.start_date))
        self.client.force_authenticate(self.member)
        for author in authors:
            for index in range(2):
                message = Message.objects.create(conversation=self.conversation, sender=author, text='Good progress')
                response = self.client.post(f'/api-v1/community/messages/{message.pk}/react/', {'emoji': '\u2764\ufe0f'}, format='json')
                self.assertEqual(response.status_code, 200, response.data)
                checkin = self.checkin(task, author, self.today - timedelta(days=index))
                response = self.client.post(f'/api-v1/checkins/{checkin.pk}/review/', {'approved': True}, format='json')
                self.assertEqual(response.status_code, 200, response.data)
        row = self.catalog(self.member)['hype_paddie']
        self.assertTrue(row['eligible'])
        self.assertEqual([requirement['current'] for requirement in row['requirements']], [20, 5])
        self.assertEqual(self.catalog(self.owner)['hype_paddie']['current'], 0)

    def test_outsider_and_self_reactions_never_add_hype_credit(self):
        message = self.message()
        for actor, expected in ((self.outsider, 404), (self.owner, 200)):
            self.client.force_authenticate(actor)
            response = self.client.post(f'/api-v1/community/messages/{message.pk}/react/', {'emoji': '\U0001f44d'}, format='json')
            self.assertEqual(response.status_code, expected, response.data)
            self.assertEqual(self.credits(actor, 'positive_interaction').count(), 0)

    def test_positive_reaction_to_user_task_card_counts_but_scheduler_prompt_does_not(self):
        task = self.pod(member=self.member)
        card = self.message(kind='goal', metadata={'event': 'community_task_created', 'community_task_id': task.pk})
        prompt = self.message(conversation=task.goal.conversation, kind='checkin', metadata={'event': 'checkin_due'})
        self.client.force_authenticate(self.member)
        for message in (card, prompt):
            response = self.client.post(f'/api-v1/community/messages/{message.pk}/react/', {'emoji': '\U0001f44d'}, format='json')
            self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(self.catalog(self.member)['hype_paddie']['current'], 1)

    def test_milestone_actor_transition_and_retry_dedup_not_creator_credit(self):
        task = self.pod(member=self.member)
        milestone = Task.objects.create(goal=task.goal, owner=self.member, title='Owned by member')
        self.client.force_authenticate(self.member)
        for completed in (True, True, False, True):
            response = self.client.patch(f'/api-v1/tasks/{milestone.pk}/', {'completed': completed}, format='json')
            self.assertEqual(response.status_code, 200, response.data)
        credit = self.credits(self.member, 'milestone_completed').get()
        self.assertEqual(credit.metadata['actor_id'], self.member.pk)
        self.assertEqual(self.credits(kind='milestone_completed').count(), 0)

    def test_explicitly_completed_creation_records_authenticated_actor_for_both_forms(self):
        task = self.pod(member=self.member)
        self.client.force_authenticate(self.member)
        for fields in ({'completed': True}, {'status': 'completed'}):
            response = self.client.post('/api-v1/tasks/', {
                'goal': task.goal_id, 'title': 'Complete at creation', 'owner': self.owner.pk, **fields,
            }, format='json')
            self.assertEqual(response.status_code, 201, response.data)
            fact = self.credits(self.member, 'milestone_completed').get(subject_id=str(response.data['id']))
            self.assertEqual(fact.metadata['actor_id'], self.member.pk)
            self.assertEqual(fact.occurred_at.utcoffset(), timedelta(0))
        self.assertEqual(self.credits(self.member, 'milestone_completed').count(), 2)
        self.assertEqual(self.credits(kind='milestone_completed').count(), 0)
        response = self.client.post('/api-v1/tasks/', {'goal': task.goal_id, 'title': 'Not complete'}, format='json')
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(self.credits(self.member, 'milestone_completed').count(), 2)

    def test_milestone_hunter_requires_three_tasks_and_never_backfills_owner(self):
        historical = self.pod(member=self.member)
        for index in range(10):
            Task.objects.create(goal=historical.goal, owner=self.member, title='Unknown completer', completed=True)
        self.assertEqual(self.catalog(self.member)['milestone_hunter']['current'], 0)
        tasks = [historical, self.pod(member=self.member), self.pod(member=self.member)]
        self.client.force_authenticate(self.member)
        for index in range(10):
            task = tasks[index // 5]
            milestone = Task.objects.create(goal=task.goal, owner=self.member, title='Complete this')
            response = self.client.patch(f'/api-v1/tasks/{milestone.pk}/', {'status': 'completed'}, format='json')
            self.assertEqual(response.status_code, 200, response.data)
        self.assertFalse(self.catalog(self.member)['milestone_hunter']['eligible'])
        milestone = Task.objects.create(goal=tasks[2].goal, owner=self.member, title='Third pod')
        self.client.patch(f'/api-v1/tasks/{milestone.pk}/', {'completed': True}, format='json')
        self.assertTrue(self.catalog(self.member)['milestone_hunter']['eligible'])

    def test_partner_approval_credits_approver_not_task_owner(self):
        task = self.pod(member=self.member)
        partnership = Partnership.objects.create(user_a=self.owner, user_b=self.member)
        milestone = Task.objects.create(goal=task.goal, owner=self.owner, title='Review this', partnership=partnership, status='pending_review')
        self.client.force_authenticate(self.member)
        response = self.client.post(f'/api-v1/tasks/{milestone.pk}/approve/')
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(self.credits(self.member, 'milestone_completed').count(), 1)
        self.assertEqual(self.credits(kind='milestone_completed').count(), 0)

    def test_approval_does_not_infer_actor_of_already_completed_legacy_milestone(self):
        task = self.pod(member=self.member)
        partnership = Partnership.objects.create(user_a=self.owner, user_b=self.member)
        milestone = Task.objects.create(goal=task.goal, owner=self.owner, title='Already complete', partnership=partnership,
                                        completed=True, status='pending_review')
        self.client.force_authenticate(self.member)
        response = self.client.post(f'/api-v1/tasks/{milestone.pk}/approve/')
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(self.credits(self.member, 'milestone_completed').count(), 0)

    def test_comeback_same_pod_miss_and_three_on_time_historical_submissions(self):
        task = self.pod(days=3)
        for offset in (2, 1, 0):
            self.checkin(task, due=self.today - timedelta(days=offset))
        self.assertTrue(self.catalog()['comeback_kid']['eligible'])
        other = self.pod(days=4, member=self.member)
        for offset in (2, 1):
            self.checkin(other, self.member, self.today - timedelta(days=offset))
        different = self.pod(member=self.member)
        self.checkin(different, self.member)
        self.assertEqual(self.catalog(self.member)['comeback_kid']['current'], 2)
        self.checkin(other, self.member, self.today, at=self.at(self.today + timedelta(days=1)))
        self.assertFalse(self.catalog(self.member)['comeback_kid']['eligible'])

    def test_model_ten_actual_completions_accept_honest_partial_and_blocked(self):
        for index in range(10):
            task = self.pod()
            self.checkin(task, state='partial' if index % 2 else 'blocked')
            with timezone.override('Pacific/Auckland'):
                self.close(task, at=self.at(self.today + timedelta(days=1)) - timedelta(microseconds=1))
        row = self.catalog()['model_paddie']
        self.assertEqual(row['current'], 10)
        self.assertTrue(row['eligible'])
        self.assertEqual(self.credits(kind='pod_model').count(), 10)
        fact = self.credits(kind='pod_model').first()
        self.assertIn('completion_audit_id', fact.metadata)
        self.assertEqual(fact.metadata['owed_dates'], [self.today.isoformat()])

    def test_model_rejects_midnight_late_missing_and_late_submitted_cycles(self):
        late_task = self.pod()
        self.checkin(late_task)
        self.close(late_task, at=self.at(self.today + timedelta(days=1)))
        missing = self.pod(days=1)
        self.checkin(missing)
        self.close(missing)
        late_checkin = self.pod(days=1)
        self.checkin(late_checkin, due=self.today - timedelta(days=1), at=self.at(self.today))
        self.checkin(late_checkin)
        self.close(late_checkin)
        self.assertEqual(self.catalog()['model_paddie']['current'], 0)

    def test_model_first_completion_snapshot_survives_later_deadline_edit_and_reopen(self):
        task = self.pod()
        self.checkin(task)
        self.close(task, at=self.at(self.today + timedelta(days=1)))
        task.goal.target_date = self.today + timedelta(days=10)
        task.goal.save(update_fields=['target_date'])
        self.close(task, state='active', at=self.at(self.today + timedelta(days=1), 1))
        self.close(task, at=self.at(self.today + timedelta(days=1), 2))
        self.assertEqual(self.catalog()['model_paddie']['current'], 0)
        self.assertEqual(self.credits(kind='pod_completed').get().metadata['target_date'], self.today.isoformat())

    def test_archive_and_unproven_historical_completion_do_not_qualify(self):
        task = self.pod()
        self.checkin(task)
        self.close(task, state='archived')
        historical = self.pod()
        historical.status = 'completed'
        historical.save(update_fields=['status'])
        rows = self.catalog()
        self.assertEqual(rows['model_paddie']['current'], 0)
        self.assertEqual(rows['no_ghosting']['current'], 0)

    def test_no_ghosting_voluntary_leave_rejoin_and_exact_28_day_threshold(self):
        task = self.pod(member=self.member)
        with patch('api.community_services.timezone.now', return_value=self.at(self.today, 8)):
            leave_task(task, self.member, 'Voluntary leave')
        with patch('api.community_services.timezone.now', return_value=self.at(self.today, 9)):
            join_task(task, self.member)
        self.close(task)
        self.assertEqual(self.credits(self.member, 'pod_reliable').count(), 0)
        old = self.pod()
        self.owner.last_login = self.now - timedelta(days=28)
        self.owner.save(update_fields=['last_login'])
        self.close(old)
        self.assertFalse(self.credits(kind='pod_reliable').filter(subject_id=str(old.pk)).exists())
        almost = self.pod()
        self.owner.last_login = self.now - timedelta(days=28) + timedelta(microseconds=1)
        self.owner.save(update_fields=['last_login'])
        self.close(almost)
        self.assertTrue(self.credits(kind='pod_reliable').filter(subject_id=str(almost.pk)).exists())

    def test_inactivity_review_or_relogin_never_erases_observed_gap(self):
        task = self.pod()
        self.owner.last_login = self.now - timedelta(days=28)
        self.owner.save(update_fields=['last_login'])
        with patch('api.community_services.timezone.now', return_value=self.now):
            review_inactive_members(now=self.now)
        self.assertEqual(task.memberships.get(user=self.owner).state, 'active')
        CommunityInactivityReview.objects.filter(user=self.owner).update(resolved=True)
        _set_last_login(self.owner, at=self.now)
        self.close(task)
        self.assertFalse(self.credits(kind='pod_reliable').exists())

    def test_future_inactivity_observation_does_not_affect_completion_replay(self):
        task = self.pod()
        record_pod_inactivity(self.owner, task.pk, self.now, self.now + timedelta(days=29))
        self.close(task)
        self.assertEqual(self.credits(kind='pod_reliable').count(), 1)

    def test_login_committed_while_waiting_for_user_lock_uses_fresh_locked_state(self):
        task = self.pod()
        self.owner.__class__.objects.filter(pk=self.owner.pk).update(last_login=self.now - timedelta(days=28))
        fresh_login = self.now - timedelta(seconds=1)
        original_lock, injected = achievements._lock_user, False

        def login_committed_while_waiting(user):
            nonlocal injected
            if not injected:
                injected = True
                user.__class__.objects.filter(pk=user.pk).update(last_login=fresh_login)
            return original_lock(user)

        with patch('api.achievements._lock_user', side_effect=login_committed_while_waiting):
            self.close(task)
        fact = self.credits(kind='pod_completed').get()
        self.assertEqual(fact.metadata['last_login_at'], fresh_login.isoformat())
        self.assertTrue(fact.metadata['reliable'])
        self.assertEqual(self.credits(kind='pod_inactive').count(), 0)

    def test_pause_and_resume_do_not_invent_owed_cycles(self):
        task = self.pod(days=4)
        first, resume = self.today - timedelta(days=4), self.today
        self.checkin(task, due=first)
        self.close(task, state='frozen', at=self.at(first, 20))
        self.close(task, state='active', at=self.at(resume, 8))
        self.checkin(task, due=resume)
        task.refresh_from_db()
        member = task.memberships.get(user=self.owner)
        self.assertEqual(_owed_dates(task, member, self.now), {first, resume})
        self.close(task)
        self.assertEqual(self.credits(kind='pod_model').count(), 1)

    def test_completion_while_frozen_does_not_invent_stopped_dates(self):
        task = self.pod(days=4)
        first = self.today - timedelta(days=4)
        self.checkin(task, due=first)
        self.close(task, state='frozen', at=self.at(first, 20))
        self.close(task)
        fact = self.credits(kind='pod_model').get()
        self.assertEqual(fact.metadata['owed_dates'], [first.isoformat()])

    def test_cadence_edit_preserves_missing_old_obligations(self):
        task = self.pod(days=2)
        self.checkin(task, due=self.today)
        self.client.force_authenticate(self.owner)
        with patch('api.community_views.timezone.now', return_value=self.now):
            response = self.client.patch(f'/api-v1/community/tasks/{task.pk}/', {'checkin_frequency': 'WEEKLY'}, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        self.close(task)
        self.assertEqual(self.credits(kind='pod_model').count(), 0)
        snapshot = self.credits(kind='pod_completed').get()
        self.assertEqual(len(snapshot.metadata['owed_dates']), 3)

    def test_comeback_after_resume_counts_no_paused_cycles(self):
        task = self.pod(days=6)
        first = self.today - timedelta(days=6)
        self.close(task, state='frozen', at=self.at(first, 20))
        resume = self.today - timedelta(days=2)
        self.close(task, state='active', at=self.at(resume, 8))
        for offset in (2, 1, 0):
            self.checkin(task, due=self.today - timedelta(days=offset))
        row = self.catalog()['comeback_kid']
        self.assertTrue(row['eligible'])
        fact = self.credits(kind='comeback').get()
        self.assertEqual(fact.metadata['missed_due_date'], first.isoformat())
        self.assertEqual(len(fact.metadata['checkin_ids']), 3)

    def test_capacity_limit_edit_snapshots_qualification_without_rewriting_it(self):
        task = self.pod(member=self.member, member_limit=8)
        self.assertEqual(self.catalog()['pod_magnet']['current'], 0)
        self.client.force_authenticate(self.internal)
        response = self.client.post(f'/api-v1/community/tasks/{task.pk}/limits/',
                                    {'member_limit': 2, 'reason': 'Smaller pod'}, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        fact = self.credits(kind='pod_capacity').get()
        self.assertEqual(fact.metadata['member_limit'], 2)
        response = self.client.post(f'/api-v1/community/tasks/{task.pk}/limits/',
                                    {'member_limit': 8, 'reason': 'Larger pod'}, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        fact.refresh_from_db()
        self.assertEqual(fact.metadata['member_limit'], 2)
        self.assertEqual(self.catalog()['pod_magnet']['current'], 1)

    def test_late_deadline_extension_never_invents_gap_cycles_or_false_comeback(self):
        task = self.pod(days=4, target=self.today - timedelta(days=2))
        for offset in (4, 3, 2):
            self.checkin(task, due=self.today - timedelta(days=offset))
        self.client.force_authenticate(self.internal)
        with patch('api.community_views.timezone.now', return_value=self.now):
            response = self.client.post(f'/api-v1/community/tasks/{task.pk}/limits/', {
                'target_date': self.today.isoformat(), 'reason': 'Extend today',
            }, format='json')
            self.assertEqual(response.status_code, 200, response.data)
            generate_task_cycles(task)
        self.assertFalse(task.goal.checkins.filter(scheduled_for=self.today - timedelta(days=1)).exists())
        self.checkin(task)
        self.close(task)
        fact = self.credits(kind='pod_completed').get()
        self.assertNotIn((self.today - timedelta(days=1)).isoformat(), fact.metadata['owed_dates'])
        self.assertTrue(fact.metadata['model'])
        self.assertEqual(len(fact.metadata['owed_dates']), 4)
        self.assertEqual(self.catalog()['comeback_kid']['current'], 0)

    def test_deadline_extension_does_not_forget_missing_original_obligations(self):
        task = self.pod(days=4, target=self.today - timedelta(days=2))
        for offset in (4, 2):
            self.checkin(task, due=self.today - timedelta(days=offset))
        self.client.force_authenticate(self.internal)
        with patch('api.community_views.timezone.now', return_value=self.now):
            response = self.client.post(f'/api-v1/community/tasks/{task.pk}/limits/', {
                'target_date': self.today.isoformat(), 'reason': 'Extend today',
            }, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        self.checkin(task)
        self.close(task)
        fact = self.credits(kind='pod_completed').get()
        self.assertIn((self.today - timedelta(days=3)).isoformat(), fact.metadata['owed_dates'])
        self.assertFalse(fact.metadata['model'])

    def test_overlapping_closures_lock_members_in_user_id_order(self):
        task = self.pod(member=self.other)
        self.admit_pod(task, self.member, joined_at=self.at(self.today))
        visited = []
        with patch('api.achievements.evaluate_achievements', side_effect=lambda user: visited.append(user.pk)):
            self.close(task)
        self.assertEqual(visited, sorted([self.owner.pk, self.member.pk, self.other.pk]))


class AchievementMigrationTests(SimpleTestCase):
    def test_migration_passes_existing_additive_auto_deployment_policy(self):
        from deployment.automatic.migration_policy import migration_plan_violations
        migration_type = import_module('api.migrations.0038_achievement_credits').Migration
        migration = migration_type('0038_achievement_credits', 'api')
        self.assertEqual(migration_plan_violations([(migration, False)]), [])

    def test_isolated_openapi_contract_imports_and_names_the_achievement_key(self):
        from django.urls import include, path
        from drf_spectacular.generators import SchemaGenerator
        from drf_spectacular.validation import validate_schema
        from rest_framework.routers import SimpleRouter
        from .achievement_views import AchievementViewSet
        router = SimpleRouter()
        router.register('achievements', AchievementViewSet, basename='achievements')
        schema = SchemaGenerator(patterns=[path('api-v1/', include(router.urls))]).get_schema(public=True)
        validate_schema(schema)
        claim = schema['paths']['/api-v1/achievements/{key}/claim/']['post']
        self.assertEqual(claim['parameters'][0]['schema']['enum'], sorted(definition.key for definition in ACHIEVEMENTS))
        self.assertEqual(claim['responses']['200']['content']['application/json']['schema']['$ref'], '#/components/schemas/Achievement')
        self.assertIn('/api-v1/achievements/', schema['paths'])
