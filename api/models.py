import uuid

from django.conf import settings
from django.db import models

from padluppcore.utils.constants import StatusEnum
from padluppcore.utils.models import TimeStampedModel


def build_goal_invite_link(shared_id) -> str:
	base_url = (getattr(settings, 'PADLUPP_APP_URL', '') or 'https://app.padlupp.com').rstrip('/')
	return f'{base_url}/goals/?shared_id={shared_id}'


class Profile(TimeStampedModel):
	user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='profile')
	bio = models.TextField(blank=True)
	experience = models.TextField(blank=True)
	interests = models.TextField(blank=True, null=True, help_text='additional interests added as comma separated values')
	location = models.CharField(max_length=255, blank=True)
	time_zone = models.CharField(max_length=100, blank=True)
	focus_areas = models.JSONField(default=list, blank=True)
	availability = models.JSONField(default=dict, blank=True)
	communication_styles = models.JSONField(default=list, blank=True)



class Goal(TimeStampedModel):
	CHECKIN_DAILY = 'DAILY'
	CHECKIN_3_DAYS = '3-DAYS'
	CHECKIN_WEEKLY = 'WEEKLY'
	CHECKIN_BI_WEEKLY = 'BI-WEEKLY'
	CHECKIN_MONDAYS = 'MONDAYS'
	CHECKIN_TUESDAYS = 'TUESDAYS'
	CHECKIN_WEDNESDAYS = 'WEDNESDAYS'
	CHECKIN_THURSDAYS = 'THURSDAYS'
	CHECKIN_FRIDAYS = 'FRIDAYS'
	CHECKIN_SATURDAYS = 'SATURDAYS'
	# Legacy typo support for already-persisted values.
	CHECKIN_SARTUDAYS = 'SARTUDAYS'
	CHECKIN_SUNDAYS = 'SUNDAYS'

	CHECKIN_FREQUENCY_CHOICES = [
		(CHECKIN_DAILY, 'Daily'),
		(CHECKIN_3_DAYS, 'Every 3 Days'),
		(CHECKIN_WEEKLY, 'Weekly'),
		(CHECKIN_BI_WEEKLY, 'Bi-Weekly'),
		(CHECKIN_MONDAYS, 'Mondays'),
		(CHECKIN_TUESDAYS, 'Tuesdays'),
		(CHECKIN_WEDNESDAYS, 'Wednesdays'),
		(CHECKIN_THURSDAYS, 'Thursdays'),
		(CHECKIN_FRIDAYS, 'Fridays'),
		(CHECKIN_SATURDAYS, 'Saturdays'),
		(CHECKIN_SUNDAYS, 'Sundays'),
	]

	user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='goals')
	partnership = models.ForeignKey('Partnership', on_delete=models.CASCADE, related_name='goals', null=True, blank=True, help_text='If set, this goal is shared with the partnership.')
	members = models.ManyToManyField(settings.AUTH_USER_MODEL, through='GoalMembership', through_fields=('goal', 'user'), related_name='member_goals', blank=True)
	title = models.CharField(max_length=255)
	category = models.CharField(max_length=100, blank=True)
	importance = models.CharField(max_length=20, blank=True)
	checkin_frequency = models.CharField(max_length=20, choices=CHECKIN_FREQUENCY_CHOICES, default=CHECKIN_DAILY)
	is_public = models.BooleanField(default=False)
	is_shared = models.BooleanField(default=False)
	shared_id = models.UUIDField(null=True, blank=True, unique=True)
	invite_link = models.URLField(null=True, blank=True)
	description = models.TextField(blank=True)
	start_date = models.DateField(null=True, blank=True)
	start_time = models.TimeField(null=True, blank=True)
	target_date = models.DateField(null=True, blank=True)
	status = models.CharField(max_length=20, default=StatusEnum.PENDING.value)
	is_active = models.BooleanField(default=True)

	def save(self, *args, **kwargs):
		if self.is_public:
			if not self.shared_id:
				self.shared_id = uuid.uuid4()
			if not self.invite_link and self.shared_id:
				self.invite_link = build_goal_invite_link(self.shared_id)
		super().save(*args, **kwargs)


class GoalMembership(TimeStampedModel):
	goal = models.ForeignKey(Goal, on_delete=models.CASCADE, related_name='goal_memberships')
	user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='goal_memberships')
	added_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, related_name='added_goal_memberships', null=True, blank=True)

	class Meta:
		constraints = [
			models.UniqueConstraint(fields=['goal', 'user'], name='uniq_goal_member'),
		]
		indexes = [
			models.Index(fields=['goal', 'user']),
		]


class Partnership(TimeStampedModel):
	user_a = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='partnerships_as_a')
	user_b = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='partnerships_as_b')
	is_active = models.BooleanField(default=True)
	paused = models.BooleanField(default=False)
	focus_goals = models.ManyToManyField(Goal, related_name='partnerships', blank=True)

	class Meta:
		unique_together = ('user_a', 'user_b')


class Event(TimeStampedModel):
	title = models.CharField(max_length=255)
	description = models.TextField(blank=True)
	start_date = models.DateField()
	start_time = models.TimeField()
	end_date = models.DateField()
	end_time = models.TimeField()
	banner = models.ImageField(upload_to='event_banners/', null=True, blank=True)
	event_link = models.URLField(blank=True)
	reminder_sent = models.BooleanField(default=False)
	creator = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='events_created')
	participants = models.ManyToManyField(settings.AUTH_USER_MODEL, related_name='events_participating', blank=True)


class Match(TimeStampedModel):
	LIKE = 'like'
	PASS = 'pass'
	ACTION_CHOICES = [
		(LIKE, 'Like'),
		(PASS, 'Pass'),
	]

	from_user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='matches_sent')
	to_user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='matches_received')
	action = models.CharField(max_length=10, choices=ACTION_CHOICES)

	class Meta:
		unique_together = ('from_user', 'to_user')


class BuddyRequest(TimeStampedModel):
	STATUS_PENDING = 'pending'
	STATUS_ACCEPTED = 'accepted'
	STATUS_REJECTED = 'rejected'

	STATUS_CHOICES = [
		(STATUS_PENDING, 'Pending'),
		(STATUS_ACCEPTED, 'Accepted'),
		(STATUS_REJECTED, 'Rejected'),
	]

	from_user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='buddy_requests_sent')
	to_user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='buddy_requests_received')
	status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)
	message = models.TextField(blank=True, default='')
	responded_at = models.DateTimeField(null=True, blank=True)

	class Meta:
		unique_together = ('from_user', 'to_user')
		indexes = [
			models.Index(fields=['to_user', 'status']),
			models.Index(fields=['from_user', 'status']),
		]


class Task(TimeStampedModel):
	STATUS_PLANNED = 'planned'
	STATUS_IN_PROGRESS = 'in_progress'
	STATUS_PENDING_REVIEW = 'pending_review'
	STATUS_COMPLETED = 'completed'
	STATUS_NEEDS_REVISION = 'needs_revision'
	STATUS_NOT_COMPLETED = 'not_completed'

	STATUS_CHOICES = [
		(STATUS_PLANNED, 'Planned'),
		(STATUS_IN_PROGRESS, 'In progress'),
		(STATUS_PENDING_REVIEW, 'Pending partner review'),
		(STATUS_COMPLETED, 'Completed'),
		(STATUS_NEEDS_REVISION, 'Needs revision'),
		(STATUS_NOT_COMPLETED, 'Not completed'),
	]

	goal = models.ForeignKey(Goal, on_delete=models.CASCADE, related_name='tasks')
	partnership = models.ForeignKey(Partnership, on_delete=models.CASCADE, related_name='tasks', null=True, blank=True)
	owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='tasks')
	title = models.CharField(max_length=255)
	completed = models.BooleanField(default=False)
	description = models.TextField(blank=True)
	due_at = models.DateTimeField(null=True, blank=True)
	status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PLANNED)
	is_shared = models.BooleanField(default=False)
	is_overdue = models.BooleanField(default=False)


class SubTask(TimeStampedModel):
	task = models.ForeignKey(Task, on_delete=models.CASCADE, related_name='subtasks')
	owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='subtasks', null=True, blank=True)
	title = models.CharField(max_length=255)
	description = models.TextField(blank=True)
	status = models.CharField(max_length=20, choices=Task.STATUS_CHOICES, default=Task.STATUS_PLANNED)


class TimerSession(TimeStampedModel):
	task = models.ForeignKey(Task, on_delete=models.CASCADE, related_name='timer_sessions', null=True, blank=True)
	subtask = models.ForeignKey(SubTask, on_delete=models.CASCADE, related_name='timer_sessions', null=True, blank=True)
	user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='timer_sessions')
	started_at = models.DateTimeField()
	ended_at = models.DateTimeField(null=True, blank=True)
	notes = models.TextField(blank=True)


class Evidence(TimeStampedModel):
	task = models.ForeignKey(Task, on_delete=models.CASCADE, related_name='evidences')
	subtask = models.ForeignKey(SubTask, on_delete=models.CASCADE, related_name='evidences', null=True, blank=True)
	submitted_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='evidences')
	text = models.TextField(blank=True)
	files = models.FileField(upload_to='evidence_files/', blank=True, null=True)
	links = models.URLField(blank=True, null=True)
	submitted_at = models.DateTimeField(auto_now_add=True)
	reviewed_at = models.DateTimeField(null=True, blank=True)
	approved = models.BooleanField(null=True, blank=True)
	reviewer = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='evidence_reviews')


class Notification(TimeStampedModel):
	user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='notifications')
	type = models.CharField(max_length=50)
	payload = models.JSONField(default=dict, blank=True)
	is_read = models.BooleanField(default=False)


class UserDailyActivity(TimeStampedModel):
	"""One record per user per local calendar day with activity metadata."""

	user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='daily_activities')
	activity_date = models.DateField()
	first_activity_at = models.DateTimeField()
	last_activity_at = models.DateTimeField()
	source = models.CharField(max_length=50, blank=True, default='')

	class Meta:
		constraints = [
			models.UniqueConstraint(fields=['user', 'activity_date'], name='uniq_user_activity_date'),
		]
		indexes = [
			models.Index(fields=['user', 'activity_date']),
		]


class InactivityNudgeLog(TimeStampedModel):
	"""Tracks inactivity nudges already sent for a given inactivity span."""

	user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='inactivity_nudge_logs')
	latest_activity_at = models.DateTimeField()
	threshold_days = models.PositiveSmallIntegerField(default=14)

	class Meta:
		constraints = [
			models.UniqueConstraint(
				fields=['user', 'latest_activity_at', 'threshold_days'],
				name='uniq_inactivity_nudge_user_activity_threshold',
			),
		]
		indexes = [
			models.Index(fields=['user', 'threshold_days']),
			models.Index(fields=['latest_activity_at']),
		]


class CheckinReminderLog(TimeStampedModel):
	"""Tracks per-goal check-in reminders sent for a specific reminder date."""

	goal = models.ForeignKey(Goal, on_delete=models.CASCADE, related_name='checkin_reminder_logs')
	user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='checkin_reminder_logs')
	reminder_for_date = models.DateField()
	frequency = models.CharField(max_length=20)

	class Meta:
		constraints = [
			models.UniqueConstraint(
				fields=['goal', 'user', 'reminder_for_date'],
				name='uniq_goal_user_checkin_reminder_for_date',
			),
		]
		indexes = [
			models.Index(fields=['reminder_for_date', 'frequency']),
		]


class Conversation(TimeStampedModel):
	partnership = models.OneToOneField(Partnership, on_delete=models.CASCADE, related_name='conversation', null=True, blank=True)
	goal = models.OneToOneField(Goal, on_delete=models.CASCADE, related_name='conversation', null=True, blank=True)
	name = models.CharField(max_length=255, blank=True, default='')
	is_group = models.BooleanField(default=False)
	members = models.ManyToManyField(settings.AUTH_USER_MODEL, through='ConversationMembership', through_fields=('conversation', 'user'), related_name='conversations', blank=True)


class ConversationMembership(TimeStampedModel):
	conversation = models.ForeignKey(Conversation, on_delete=models.CASCADE, related_name='conversation_memberships')
	user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='conversation_memberships')
	added_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, related_name='added_conversation_memberships', null=True, blank=True)

	class Meta:
		constraints = [
			models.UniqueConstraint(fields=['conversation', 'user'], name='uniq_conversation_member'),
		]
		indexes = [
			models.Index(fields=['conversation', 'user']),
		]


class Message(TimeStampedModel):
	conversation = models.ForeignKey(Conversation, on_delete=models.CASCADE, related_name='messages')
	sender = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='messages')
	text = models.TextField(blank=True, default='')
	reply_to_message = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True, related_name='reply_messages')
	is_a_reply = models.BooleanField(default=False)
	attachment = models.FileField(upload_to='chat_attachments/', null=True, blank=True)
	attachment_name = models.CharField(max_length=255, blank=True, default='')
	attachment_mime = models.CharField(max_length=100, blank=True, default='')
	attachment_size = models.PositiveIntegerField(null=True, blank=True)
	is_read = models.BooleanField(default=False)


class Waitlister(TimeStampedModel):
	email = models.EmailField(unique=True)
	name = models.CharField(max_length=255, blank=True)
	age = models.IntegerField(null=True, blank=True)
	sex = models.CharField(max_length=10, blank=True)
	country = models.CharField(max_length=100, blank=True)