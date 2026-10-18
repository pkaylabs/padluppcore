from datetime import datetime, time, timedelta, timezone as datetime_timezone
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import override_settings
from django.utils import timezone
from rest_framework.test import APITestCase

from .awards import AWARD_DEFINITIONS, awards_payload_for_user
from .community_models import CommunityAudit, CommunityCategory, CommunityTask, CommunityTaskPeriod
from .community_services import (
    COMMUNITY_CHECKIN_REMINDER_HOUR_UTC, generate_task_cycles, invite_task_users, join_task, leave_task,
)
from .models import GoalCheckin, GoalCheckinBadge, Message, Notification, UserAward


class CheckinFixture:
    start_offset = -2

    def setUp(self):
        super().setUp()
        self.today = timezone.now().astimezone(datetime_timezone.utc).date()
        self.now = self.at(self.today, 9)
        self.owner = get_user_model().objects.create(name='Pod owner', email='closure-owner@example.test', is_founder=True)
        self.client.force_authenticate(self.owner)
        category = CommunityCategory.objects.get(name='Educational')
        with patch('api.community_services.timezone.now', return_value=self.now):
            response = self.client.post('/api-v1/community/groups/', {'name': 'Check-in group', 'category': category.id}, format='json')
            self.assertEqual(response.status_code, 201, response.data)
            self.start = self.today + timedelta(days=self.start_offset)
            response = self.client.post('/api-v1/community/tasks/', {
                'group': response.data['id'], 'title': 'Honest participation', 'description': 'Keep showing up',
                'category': 'Educational', 'start_date': self.start.isoformat(),
                'target_date': (self.today + timedelta(days=8)).isoformat(),
                'invitation_deadline': (self.now + timedelta(days=1)).isoformat(),
                'member_limit': 8, 'visibility': 'public', 'approval_required': False,
                'checkin_frequency': 'DAILY', 'idempotency_key': 'closure-checkins',
            }, format='json')
        self.assertEqual(response.status_code, 201, response.data)
        self.task = CommunityTask.objects.get(pk=response.data['id'])
        self.membership = self.task.memberships.get(user=self.owner)
        self.set_period(self.membership, self.at(self.start, 0))
        Notification.objects.filter(type__startswith='community_checkin_').delete()

    @staticmethod
    def at(date, hour, minute=0):
        return datetime.combine(date, time(hour, minute), tzinfo=datetime_timezone.utc)

    def set_period(self, member, start, end=None):
        member.joined_at = start
        member.left_at = end
        member.save(update_fields=['joined_at', 'left_at'])
        member.periods.all().delete()
        CommunityTaskPeriod.objects.create(membership=member, joined_at=start, ended_at=end)

    def member(self, name):
        user = get_user_model().objects.create(name=name, email=name.lower() + '@example.test')
        with patch('api.community_services.timezone.now', return_value=self.now):
            invite_task_users(self.task, self.owner, [user.id])
            join_task(self.task, user, invited=True)
        return user, self.task.memberships.get(user=user)

    def submit(self, user, date, *, status='partial', percent=0, submitted_at=None):
        row, _ = GoalCheckin.objects.get_or_create(goal=self.task.goal, user=user, scheduled_for=date)
        GoalCheckin.objects.filter(pk=row.pk).update(
            status=status, completion_percent=percent, submitted_at=submitted_at or self.at(date, 12),
            update_text='Honest update', review_status='clarification',
        )
        return row

    def fill(self, user):
        for day in range((self.today - self.start).days + 1):
            self.submit(user, self.start + timedelta(days=day))

    def close(self, status='completed'):
        with patch('api.community_services.timezone.now', return_value=self.at(self.today, 22)):
            response = self.client.post(f'/api-v1/community/tasks/{self.task.id}/lifecycle/',
                                        {'status': status, 'reason': 'Pod closure'}, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        self.task.refresh_from_db()


@override_settings(SECURE_SSL_REDIRECT=False, ALLOWED_HOSTS=['testserver'], EMAIL_NOTIFICATIONS_ENABLED=False, FIREBASE_PUSH_ENABLED=False)
class PodClosureAwardTests(CheckinFixture, APITestCase):
    def test_honest_zero_progress_late_and_unconfirmed_submissions_earn_on_closure(self):
        for day, status in enumerate(('completed', 'partial', 'blocked')):
            self.submit(self.owner, self.start + timedelta(days=day), status=status, percent=0,
                        submitted_at=self.at(self.today, 21))
        self.assertTrue(self.task.goal.checkins.filter(scheduled_for__gt=self.today, submitted_at__isnull=True).exists())
        cycle_badge = GoalCheckinBadge.objects.create(goal=self.task.goal, scheduled_for=self.today)
        self.close()
        award = UserAward.objects.get(user=self.owner, award_key='consistent_checkins')
        self.assertEqual(award.progress_snapshot, 3)
        self.assertTrue(GoalCheckinBadge.objects.filter(pk=cycle_badge.pk).exists())
        entry = CommunityAudit.objects.get(task=self.task, action='task.checkin_awards_evaluated')
        self.assertEqual(entry.actor_id, self.owner.id)
        self.assertEqual(entry.outcome['awarded_user_ids'], [self.owner.id])

    def test_missing_pending_cycle_and_absent_due_row_each_prevent_award(self):
        self.fill(self.owner)
        GoalCheckin.objects.filter(goal=self.task.goal, user=self.owner, scheduled_for=self.start).update(status='pending', submitted_at=None)
        self.close()
        self.assertFalse(UserAward.objects.filter(user=self.owner, award_key='consistent_checkins').exists())
        GoalCheckin.objects.filter(goal=self.task.goal, user=self.owner, scheduled_for=self.start).delete()
        self.close('archived')
        self.assertFalse(UserAward.objects.filter(user=self.owner, award_key='consistent_checkins').exists())

    def test_zero_issued_due_cycles_and_future_rows_do_not_earn_award(self):
        self.task.goal.checkins.filter(scheduled_for__lte=self.today).delete()
        self.close('deleted')
        self.assertFalse(UserAward.objects.filter(user=self.owner, award_key='consistent_checkins').exists())

    def test_repeated_completed_archived_deleted_closure_is_idempotent_and_awards_api_is_coherent(self):
        self.fill(self.owner)
        for status in ('completed', 'archived', 'deleted', 'archived'):
            self.close(status)
        self.assertEqual(UserAward.objects.filter(user=self.owner, award_key='consistent_checkins').count(), 1)
        notices = Notification.objects.filter(user=self.owner, type='milestone_unlocked', payload__award_key='consistent_checkins')
        self.assertEqual(notices.count(), 1)
        self.assertEqual(notices.get().payload['path'], '/milestones')
        payload = awards_payload_for_user(self.owner)
        self.assertEqual(payload['total_count'], len(AWARD_DEFINITIONS))
        self.assertEqual(payload['total_count'], 9)
        team = next(category for category in payload['categories'] if category['key'] == 'team_player')
        badge = next(item for item in team['awards'] if item['key'] == 'consistent_checkins')
        self.assertEqual((badge['title'], badge['current'], badge['target'], badge['unlocked']), ('Consistent check-ins', 1, 1, True))
        self.assertEqual(payload['unlocked_count'], sum(item['unlocked'] for category in payload['categories'] for item in category['awards']))

    def test_freeze_disable_and_cancel_do_not_award(self):
        self.fill(self.owner)
        for status in ('frozen', 'disabled', 'cancelled'):
            self.close(status)
        self.assertFalse(UserAward.objects.filter(user=self.owner, award_key='consistent_checkins').exists())
        self.assertFalse(CommunityAudit.objects.filter(task=self.task, action='task.checkin_awards_evaluated').exists())

    def test_active_late_joiner_is_not_required_to_submit_prejoin_cycles(self):
        user, member = self.member('LateJoiner')
        self.set_period(member, self.at(self.today, 0))
        self.submit(user, self.today, status='blocked')
        self.close('archived')
        self.assertTrue(UserAward.objects.filter(user=user, award_key='consistent_checkins').exists())
        self.assertFalse(UserAward.objects.filter(user=self.owner, award_key='consistent_checkins').exists())

    def test_membership_absence_is_excluded_but_submissions_outside_authorized_period_do_not_count(self):
        user, member = self.member('Rejoined')
        self.set_period(member, self.at(self.today, 0))
        CommunityTaskPeriod.objects.create(membership=member, joined_at=self.at(self.start, 0), ended_at=self.at(self.start, 23))
        self.submit(user, self.start)
        self.submit(user, self.today)
        # This missing row falls entirely inside the voluntary absence.
        self.assertFalse(self.task.goal.checkins.filter(user=user, scheduled_for=self.today - timedelta(days=1)).exists())
        self.close()
        self.assertTrue(UserAward.objects.filter(user=user, award_key='consistent_checkins').exists())
        other, membership = self.member_after_reopen('OutOfPeriod')
        self.set_period(membership, self.at(self.today, 0))
        CommunityTaskPeriod.objects.create(membership=membership, joined_at=self.at(self.start, 0), ended_at=self.at(self.start, 23))
        self.submit(other, self.start, submitted_at=self.at(self.today - timedelta(days=1), 12))
        self.submit(other, self.today)
        self.close('archived')
        self.assertFalse(UserAward.objects.filter(user=other, award_key='consistent_checkins').exists())

    def member_after_reopen(self, name):
        self.close('active')
        return self.member(name)

    def test_inactive_removed_and_banned_members_do_not_receive_closure_award(self):
        for name, state in [('Inactive', 'active'), ('Removed', 'removed'), ('Banned', 'banned')]:
            user, member = self.member(name)
            self.set_period(member, self.at(self.start, 0))
            self.fill(user)
            if name == 'Inactive':
                get_user_model().objects.filter(pk=user.pk).update(is_active=False)
            else:
                member.state = state
                member.save(update_fields=['state'])
        self.close()
        self.assertFalse(UserAward.objects.filter(award_key='consistent_checkins').exists())


@override_settings(SECURE_SSL_REDIRECT=False, ALLOWED_HOSTS=['testserver'], EMAIL_NOTIFICATIONS_ENABLED=False, FIREBASE_PUSH_ENABLED=False)
class CommunityCycleNotificationTests(CheckinFixture, APITestCase):
    start_offset = 0

    def run_cycles(self, at):
        with patch('api.community_services.timezone.now', return_value=at):
            return generate_task_cycles(self.task, now=at)

    def events(self, event=None, user=None):
        qs = Notification.objects.filter(user=user or self.owner, type__startswith='community_checkin_')
        return qs.filter(type='community_checkin_' + event) if event else qs

    def test_due_evening_reminder_and_next_day_missed_are_each_deduplicated(self):
        self.assertEqual(COMMUNITY_CHECKIN_REMINDER_HOUR_UTC, 20)
        row = self.task.goal.checkins.get(user=self.owner, scheduled_for=self.today)
        self.run_cycles(self.at(self.today, 9))
        self.run_cycles(self.at(self.today, 19, 59))
        self.assertEqual(self.events('due').count(), 1)
        self.assertFalse(self.events('reminder').exists())
        self.run_cycles(self.at(self.today, 20))
        self.run_cycles(self.at(self.today, 23))
        self.assertEqual(self.events('reminder').count(), 1)
        next_day = self.today + timedelta(days=1)
        self.run_cycles(self.at(next_day, 0))
        self.run_cycles(self.at(next_day, 1))
        missed = self.events('missed').get()
        row.refresh_from_db()
        self.assertEqual(row.status, 'missed')
        for event in self.events().filter(payload__checkin_id=row.id):
            self.assertEqual(event.payload['goal_id'], self.task.goal_id)
            self.assertEqual(event.payload['task_id'], self.task.id)
            self.assertEqual(event.payload['checkin_id'], row.id)
            self.assertEqual(event.payload['due_date'], self.today.isoformat())
            self.assertTrue(event.payload['message'])
        self.assertEqual(missed.payload['due_date'], self.today.isoformat())
        self.assertEqual(self.events().filter(payload__checkin_id=row.id).count(), 3)

    def test_submitted_or_nonpending_rows_do_not_receive_new_notices(self):
        row = self.submit(self.owner, self.today, status='partial')
        self.run_cycles(self.at(self.today, 20))
        self.assertFalse(self.events().exists())
        GoalCheckin.objects.filter(pk=row.id).update(status='missed', submitted_at=None)
        self.run_cycles(self.at(self.today, 21))
        self.assertFalse(self.events().exists())

    def test_closed_pod_does_not_generate_due_reminder_or_missed_notices(self):
        self.close('archived')
        self.assertEqual(self.run_cycles(self.at(self.today + timedelta(days=1), 20)), 0)
        self.assertFalse(self.events().exists())

    def test_disabled_reminders_suppress_events_and_generic_chat_prompt_notices(self):
        other, _ = self.member('NoReminders')
        get_user_model().objects.filter(pk__in=[self.owner.id, other.id]).update(notify_on_reminders=False)
        Notification.objects.filter(type__startswith='community_checkin_').delete()
        Message.objects.filter(conversation=self.task.goal.conversation, kind='checkin', metadata__event='checkin_due').delete()
        before = Notification.objects.filter(type='new_message').count()
        self.run_cycles(self.at(self.today, 20))
        self.run_cycles(self.at(self.today + timedelta(days=1), 1))
        self.assertFalse(Notification.objects.filter(type__startswith='community_checkin_').exists())
        self.assertEqual(Notification.objects.filter(type='new_message').count(), before)

    def test_inactive_and_departed_members_do_not_receive_cycle_notices(self):
        inactive, _ = self.member('Disabled')
        departed, _ = self.member('Departed')
        get_user_model().objects.filter(pk=inactive.id).update(is_active=False)
        leave_task(self.task, departed, 'Other priorities')
        Notification.objects.filter(type__startswith='community_checkin_').delete()
        self.run_cycles(self.at(self.today, 20))
        self.run_cycles(self.at(self.today + timedelta(days=1), 1))
        self.assertFalse(Notification.objects.filter(user__in=[inactive, departed], type__startswith='community_checkin_').exists())

    def assert_resume_does_not_create_paused_cycles(self, paused_status):
        original = self.task.goal.checkins.get(user=self.owner, scheduled_for=self.today)
        self.close(paused_status)
        self.assertFalse(self.task.goal.checkins.filter(scheduled_for__gt=self.today).exists())
        # Reconcile an unused future placeholder left by the previous scheduler.
        paused_date = self.today + timedelta(days=1)
        unused = GoalCheckin.objects.create(goal=self.task.goal, user=self.owner, scheduled_for=paused_date)
        resumed = self.today + timedelta(days=3)
        with patch('api.community_services.timezone.now', return_value=self.at(resumed, 9)):
            response = self.client.post(f'/api-v1/community/tasks/{self.task.id}/lifecycle/', {'status': 'active'}, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        self.task.refresh_from_db()
        self.assertEqual(self.task.checkin_schedule_effective_from, resumed)
        self.assertTrue(GoalCheckin.objects.filter(pk=original.pk).exists())
        self.assertFalse(GoalCheckin.objects.filter(pk=unused.pk).exists())
        for at in (self.at(resumed, 20), self.at(resumed + timedelta(days=1), 9)):
            self.run_cycles(at)
        paused_days = [self.today + timedelta(days=1), self.today + timedelta(days=2)]
        self.assertFalse(self.task.goal.checkins.filter(scheduled_for__in=paused_days).exists())
        self.assertFalse(self.events('missed').filter(payload__due_date__in=[day.isoformat() for day in paused_days]).exists())

    def test_frozen_pod_resume_preserves_history_without_paused_misses(self):
        self.assert_resume_does_not_create_paused_cycles('frozen')

    def test_disabled_pod_resume_preserves_history_without_paused_misses(self):
        self.assert_resume_does_not_create_paused_cycles('disabled')
