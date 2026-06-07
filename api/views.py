from datetime import timedelta

from django.conf import settings
from django.db.models import F, Max, Q
from django.db.models.functions import Coalesce
from django.utils import timezone
from django.utils.html import escape
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.models import User
from padluppcore.utils.email import EmailSendError, send_mailgun_email

from .activity import get_user_tzinfo
from .models import CheckinReminderLog, Goal, InactivityNudgeLog
from .nudges import build_inactivity_nudge_email


def _notification_email_for_user(user) -> str:
	return (
		getattr(user, 'preferred_notification_email', None)
		or getattr(user, 'email', None)
		or ''
	).strip()


class InactiveUserNudgeView(APIView):
	"""Send nudges to users who have been inactive for a configurable threshold.

	This endpoint is intentionally unauthenticated so a cron job can call it directly.
	It is idempotent for a given user/inactivity span via InactivityNudgeLog.
	"""

	authentication_classes = []
	permission_classes = [AllowAny]

	def post(self, request):
		threshold_days = 14
		cutoff = timezone.now() - timedelta(days=threshold_days)

		users = (
			User.objects.filter(is_active=True, deleted=False, notify_on_reminders=True)
			.exclude(Q(email__isnull=True) | Q(email=''))
			.annotate(latest_daily_activity_at=Max('daily_activities__last_activity_at'))
			.annotate(latest_activity_at=Coalesce('latest_daily_activity_at', 'last_login', 'created_at'))
			.filter(latest_activity_at__lte=cutoff)
			.order_by('latest_activity_at', 'id')
		)

		checked_count = 0
		nudged_count = 0
		skipped_count = 0
		failed_count = 0

		for user in users.iterator():
			checked_count += 1
			latest_activity_at = getattr(user, 'latest_activity_at', None)
			if not latest_activity_at:
				skipped_count += 1
				continue

			already_sent = InactivityNudgeLog.objects.filter(
				user=user,
				threshold_days=threshold_days,
				latest_activity_at=latest_activity_at,
			).exists()
			if already_sent:
				skipped_count += 1
				continue

			days_inactive = max((timezone.now() - latest_activity_at).days, threshold_days)
			subject, text, html = build_inactivity_nudge_email(
				name=getattr(user, 'name', '') or getattr(user, 'email', '') or 'there',
				days_inactive=days_inactive,
			)

			try:
				send_mailgun_email(
					to_email=_notification_email_for_user(user),
					subject=subject,
					text=text,
					html=html,
					tags=['inactivity_nudge', f'{threshold_days}_days'],
				)
			except EmailSendError:
				failed_count += 1
				continue

			InactivityNudgeLog.objects.create(
				user=user,
				latest_activity_at=latest_activity_at,
				threshold_days=threshold_days,
			)
			nudged_count += 1

		return Response(
			{
				'threshold_days': threshold_days,
				'cutoff_at': cutoff.isoformat(),
				'checked_count': checked_count,
				'nudged_count': nudged_count,
				'skipped_count': skipped_count,
				'failed_count': failed_count,
			},
			status=status.HTTP_200_OK,
		)


def _is_goal_due_tomorrow(goal: Goal, today_local_date, tomorrow_local_date) -> bool:
	frequency = (goal.checkin_frequency or Goal.CHECKIN_DAILY).strip().upper()

	weekday_map = {
		Goal.CHECKIN_MONDAYS: 0,
		Goal.CHECKIN_TUESDAYS: 1,
		Goal.CHECKIN_WEDNESDAYS: 2,
		Goal.CHECKIN_THURSDAYS: 3,
		Goal.CHECKIN_FRIDAYS: 4,
		Goal.CHECKIN_SATURDAYS: 5,
		Goal.CHECKIN_SARTUDAYS: 5,
		Goal.CHECKIN_SUNDAYS: 6,
	}
	if frequency in weekday_map:
		return tomorrow_local_date.weekday() == weekday_map[frequency]

	interval_days = {
		Goal.CHECKIN_DAILY: 1,
		Goal.CHECKIN_3_DAYS: 3,
		Goal.CHECKIN_WEEKLY: 7,
		Goal.CHECKIN_BI_WEEKLY: 14,
	}.get(frequency)

	if not interval_days:
		return False

	anchor_date = goal.created_at.date() if goal.created_at else today_local_date
	delta_days = (tomorrow_local_date - anchor_date).days
	return delta_days >= 0 and (delta_days % interval_days == 0)


def _checkin_recipients_for_goal(goal: Goal):
	recipients = {}
	if goal.user_id and goal.user and _notification_email_for_user(goal.user):
		recipients[goal.user_id] = goal.user

	partnership = getattr(goal, 'partnership', None)
	if partnership:
		if partnership.user_a_id and partnership.user_a and _notification_email_for_user(partnership.user_a):
			recipients[partnership.user_a_id] = partnership.user_a
		if partnership.user_b_id and partnership.user_b and _notification_email_for_user(partnership.user_b):
			recipients[partnership.user_b_id] = partnership.user_b

	return list(recipients.values())


def _build_checkin_reminder_email(*, recipient_name: str, reminders: list[dict]):
	display_name = (recipient_name or '').strip() or 'there'
	app_url = (getattr(settings, 'PADLUPP_APP_URL', '') or 'https://app.padlupp.com').rstrip('/')
	reminder_count = len(reminders)

	subject = (
		'Your Padlupp check-in reminder'
		if reminder_count == 1
		else f'Your {reminder_count} Padlupp check-in reminders'
	)
	text_items = '\n'.join(
		f'- {(item["goal_title"] or "").strip() or "Your goal"} '
		f'(due {item["due_date"].isoformat()}, {item["frequency"].lower().replace("-", " ")})'
		for item in reminders
	)
	text = (
		f'Hi {display_name},\n\n'
		'Here are your upcoming check-ins:\n\n'
		f'{text_items}\n\n'
		'Even a tiny update matters. Small steps compound, and your partner is cheering you on. '
		'You do not need to be perfect, just present.\n\n'
		f'Open Padlupp and check in: {app_url}\n\n'
		'With care,\n'
		'The Padlupp team'
	)
	html_items = ''.join(
		'<li style="margin-bottom:10px;">'
		f'<strong>{escape((item["goal_title"] or "").strip() or "Your goal")}</strong><br>'
		f'Due {item["due_date"].isoformat()} &middot; '
		f'{escape(item["frequency"].lower().replace("-", " "))}'
		'</li>'
		for item in reminders
	)
	html = (
		'<html><body style="font-family:Arial,sans-serif;line-height:1.6;color:#1f2937;">'
		f'<p>Hi {escape(display_name)},</p>'
		'<p>Here are your upcoming check-ins:</p>'
		f'<ul style="padding-left:20px;">{html_items}</ul>'
		'<p>Even a tiny update matters. Small steps compound, and your partner is cheering you on. '
		'You do not need to be perfect, just present.</p>'
		f'<p><a href="{app_url}" style="display:inline-block;padding:12px 18px;border-radius:999px;background:#17384a;color:#ffffff;text-decoration:none;font-weight:700;">Check in on Padlupp</a></p>'
		'<p>With care,<br>The Padlupp team</p>'
		'</body></html>'
	)
	return subject, text, html


class GoalCheckinReminderCronView(APIView):
	"""Send check-in reminders for goals whose cadence matches tomorrow."""

	authentication_classes = []
	permission_classes = [AllowAny]

	def post(self, request):
		now = timezone.now()

		goals = (
			Goal.objects.filter(is_active=True)
			.select_related('user', 'partnership', 'partnership__user_a', 'partnership__user_b')
			.order_by('id')
		)

		goals_checked = 0
		goals_due_tomorrow = 0
		emails_sent = 0
		emails_skipped = 0
		emails_failed = 0
		preferences_skipped = 0
		reminders_by_recipient = {}

		for goal in goals.iterator():
			goals_checked += 1
			tzinfo = get_user_tzinfo(goal.user)
			today_local = timezone.localtime(now, tzinfo).date()
			tomorrow_local = today_local + timedelta(days=1)

			if not _is_goal_due_tomorrow(goal, today_local, tomorrow_local):
				continue

			goals_due_tomorrow += 1
			frequency = (goal.checkin_frequency or Goal.CHECKIN_DAILY).strip().upper()

			for recipient in _checkin_recipients_for_goal(goal):
				if not recipient.notify_on_reminders:
					preferences_skipped += 1
					continue

				already_sent = CheckinReminderLog.objects.filter(
					goal=goal,
					user=recipient,
					reminder_for_date=tomorrow_local,
				).exists()
				if already_sent:
					emails_skipped += 1
					continue

				recipient_batch = reminders_by_recipient.setdefault(
					recipient.id,
					{'recipient': recipient, 'reminders': []},
				)
				recipient_batch['reminders'].append(
					{
						'goal': goal,
						'goal_title': goal.title,
						'due_date': tomorrow_local,
						'frequency': frequency,
					}
				)

		for recipient_batch in reminders_by_recipient.values():
			recipient = recipient_batch['recipient']
			reminders = recipient_batch['reminders']
			subject, text, html = _build_checkin_reminder_email(
				recipient_name=getattr(recipient, 'name', '') or getattr(recipient, 'email', ''),
				reminders=reminders,
			)

			try:
				send_mailgun_email(
					to_email=_notification_email_for_user(recipient),
					subject=subject,
					text=text,
					html=html,
					tags=['checkin_reminder', 'digest'],
				)
			except EmailSendError:
				emails_failed += 1
				continue

			CheckinReminderLog.objects.bulk_create(
				[
					CheckinReminderLog(
						goal=reminder['goal'],
						user=recipient,
						reminder_for_date=reminder['due_date'],
						frequency=reminder['frequency'],
					)
					for reminder in reminders
				]
			)
			emails_sent += 1

		return Response(
			{
				'goals_checked': goals_checked,
				'goals_due_tomorrow': goals_due_tomorrow,
				'emails_sent': emails_sent,
				'emails_skipped': emails_skipped,
				'emails_failed': emails_failed,
				'preferences_skipped': preferences_skipped,
			},
			status=status.HTTP_200_OK,
		)
