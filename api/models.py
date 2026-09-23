import uuid

from django.conf import settings
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models

from padluppcore.utils.constants import StatusEnum
from padluppcore.utils.models import TimeStampedModel


def build_goal_invite_link(shared_id, goal_id: int = None) -> str:
	base_url = (getattr(settings, 'PADLUPP_APP_URL', '') or 'https://app.padlupp.com').rstrip('/')
	if goal_id is not None:
		return f'{base_url}/goals/{goal_id}/preview?shared_id={shared_id}'
	return f'{base_url}/goals'


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
		else:
			self.shared_id = None
			self.invite_link = None
		super().save(*args, **kwargs)
		if self.is_public and self.shared_id:
			invite_link = build_goal_invite_link(self.shared_id, goal_id=self.id)
			if self.invite_link != invite_link:
				type(self).objects.filter(pk=self.pk).update(invite_link=invite_link)
				self.invite_link = invite_link


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
	due_at = models.DateTimeField(null=True, blank=True)
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


class DevicePushToken(TimeStampedModel):
	PLATFORM_ANDROID = 'android'
	PLATFORM_IOS = 'ios'
	PLATFORM_CHOICES = [
		(PLATFORM_ANDROID, 'Android'),
		(PLATFORM_IOS, 'iOS'),
	]

	user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='push_tokens')
	token = models.CharField(max_length=512, unique=True)
	platform = models.CharField(max_length=20, choices=PLATFORM_CHOICES)
	device_id = models.CharField(max_length=255)
	is_active = models.BooleanField(default=True)
	last_seen_at = models.DateTimeField(auto_now=True)

	class Meta:
		constraints = [
			models.UniqueConstraint(fields=['user', 'device_id'], name='uniq_push_token_user_device'),
		]
		indexes = [
			models.Index(fields=['user', 'is_active']),
		]


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


class SubTaskReminderLog(TimeStampedModel):
	"""Tracks reminder delivery for one subtask and recipient."""

	task = models.ForeignKey(Task, on_delete=models.CASCADE, related_name='reminder_logs')
	user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='subtask_reminder_logs')
	reminder_for_date = models.DateField()

	class Meta:
		constraints = [
			models.UniqueConstraint(
				fields=['task', 'user', 'reminder_for_date'],
				name='uniq_subtask_user_reminder_for_date',
			),
		]
		indexes = [models.Index(fields=['reminder_for_date'])]


class GoalCheckin(TimeStampedModel):
	STATUS_PENDING = 'pending'
	STATUS_COMPLETED = 'completed'
	STATUS_PARTIAL = 'partial'
	STATUS_BLOCKED = 'blocked'
	STATUS_MISSED = 'missed'
	STATUS_CHOICES = [
		(STATUS_PENDING, 'Pending'),
		(STATUS_COMPLETED, 'Completed'),
		(STATUS_PARTIAL, 'Partially completed'),
		(STATUS_BLOCKED, 'Blocked'),
		(STATUS_MISSED, 'Missed'),
	]

	goal = models.ForeignKey(Goal, on_delete=models.CASCADE, related_name='checkins')
	user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='goal_checkins')
	scheduled_for = models.DateField()
	status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)
	completion_percent = models.PositiveSmallIntegerField(
		default=0,
		validators=[MinValueValidator(0), MaxValueValidator(100)],
	)
	update_text = models.TextField(blank=True)
	blocker = models.TextField(blank=True)
	evidence = models.FileField(upload_to='checkin_evidence/', null=True, blank=True)
	evidence_view_once = models.BooleanField(default=False)
	evidence_expires_at = models.DateTimeField(null=True, blank=True)
	submitted_at = models.DateTimeField(null=True, blank=True)

	class Meta:
		constraints = [
			models.UniqueConstraint(
				fields=['goal', 'user', 'scheduled_for'],
				name='uniq_goal_user_checkin_date',
			),
		]
		indexes = [
			models.Index(fields=['goal', '-scheduled_for']),
			models.Index(fields=['user', '-scheduled_for']),
		]


class GoalCheckinEvidenceView(TimeStampedModel):
	checkin = models.ForeignKey(GoalCheckin, on_delete=models.CASCADE, related_name='evidence_views')
	user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='checkin_evidence_views')

	class Meta:
		constraints = [
			models.UniqueConstraint(fields=['checkin', 'user'], name='uniq_checkin_evidence_viewer'),
		]


class GoalCheckinReaction(TimeStampedModel):
	REACTION_SUPPORT = 'support'
	REACTION_CELEBRATE = 'celebrate'
	REACTION_CHOICES = [
		(REACTION_SUPPORT, 'Support'),
		(REACTION_CELEBRATE, 'Celebrate'),
	]

	checkin = models.ForeignKey(GoalCheckin, on_delete=models.CASCADE, related_name='reactions')
	user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='checkin_reactions')
	reaction = models.CharField(max_length=20, choices=REACTION_CHOICES)

	class Meta:
		constraints = [
			models.UniqueConstraint(fields=['checkin', 'user'], name='uniq_checkin_reaction_user'),
		]


class GoalCheckinBadge(TimeStampedModel):
	BADGE_FULL_PARTICIPATION = 'full_participation'

	goal = models.ForeignKey(Goal, on_delete=models.CASCADE, related_name='checkin_badges')
	scheduled_for = models.DateField()
	badge_type = models.CharField(max_length=40, default=BADGE_FULL_PARTICIPATION)

	class Meta:
		constraints = [
			models.UniqueConstraint(
				fields=['goal', 'scheduled_for', 'badge_type'],
				name='uniq_goal_checkin_badge_date_type',
			),
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
	archived_at = models.DateTimeField(null=True, blank=True)

	class Meta:
		constraints = [
			models.UniqueConstraint(fields=['conversation', 'user'], name='uniq_conversation_member'),
		]
		indexes = [
			models.Index(fields=['conversation', 'user']),
		]


class Message(TimeStampedModel):
	KIND_USER = 'user'
	KIND_GOAL = 'goal'
	KIND_CHECKIN = 'checkin'
	KIND_CHOICES = [
		(KIND_USER, 'User message'),
		(KIND_GOAL, 'Goal event'),
		(KIND_CHECKIN, 'Check-in event'),
	]

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
	recalled_at = models.DateTimeField(null=True, blank=True)
	kind = models.CharField(max_length=20, choices=KIND_CHOICES, default=KIND_USER)
	metadata = models.JSONField(default=dict, blank=True)


class UserBlock(TimeStampedModel):
	blocker = models.ForeignKey(
		settings.AUTH_USER_MODEL,
		on_delete=models.CASCADE,
		related_name='user_blocks_created',
	)
	blocked = models.ForeignKey(
		settings.AUTH_USER_MODEL,
		on_delete=models.CASCADE,
		related_name='user_blocks_received',
	)

	class Meta:
		constraints = [
			models.UniqueConstraint(fields=['blocker', 'blocked'], name='uniq_user_block'),
			models.CheckConstraint(
				condition=~models.Q(blocker=models.F('blocked')),
				name='prevent_self_block',
			),
		]
		indexes = [
			models.Index(fields=['blocker', 'blocked']),
			models.Index(fields=['blocked', 'blocker']),
		]


class ContentReport(TimeStampedModel):
	REASON_HARASSMENT = 'harassment'
	REASON_SPAM = 'spam'
	REASON_HATE_SPEECH = 'hate_speech'
	REASON_SEXUAL_CONTENT = 'sexual_content'
	REASON_VIOLENCE = 'violence'
	REASON_IMPERSONATION = 'impersonation'
	REASON_OTHER = 'other'
	REASON_CHOICES = [
		(REASON_HARASSMENT, 'Harassment or bullying'),
		(REASON_SPAM, 'Spam or scam'),
		(REASON_HATE_SPEECH, 'Hate speech'),
		(REASON_SEXUAL_CONTENT, 'Sexual content'),
		(REASON_VIOLENCE, 'Violence or threats'),
		(REASON_IMPERSONATION, 'Impersonation'),
		(REASON_OTHER, 'Other'),
	]

	STATUS_PENDING = 'pending'
	STATUS_REVIEWED = 'reviewed'
	STATUS_ACTIONED = 'actioned'
	STATUS_DISMISSED = 'dismissed'
	STATUS_CHOICES = [
		(STATUS_PENDING, 'Pending'),
		(STATUS_REVIEWED, 'Reviewed'),
		(STATUS_ACTIONED, 'Actioned'),
		(STATUS_DISMISSED, 'Dismissed'),
	]

	reporter = models.ForeignKey(
		settings.AUTH_USER_MODEL,
		on_delete=models.SET_NULL,
		null=True,
		related_name='content_reports_submitted',
	)
	reported_user = models.ForeignKey(
		settings.AUTH_USER_MODEL,
		on_delete=models.SET_NULL,
		null=True,
		related_name='content_reports_received',
	)
	conversation = models.ForeignKey(
		Conversation,
		on_delete=models.SET_NULL,
		null=True,
		blank=True,
		related_name='content_reports',
	)
	message = models.ForeignKey(
		Message,
		on_delete=models.SET_NULL,
		null=True,
		blank=True,
		related_name='content_reports',
	)
	reason = models.CharField(max_length=32, choices=REASON_CHOICES)
	details = models.TextField(blank=True, default='')
	status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)
	moderator_notes = models.TextField(blank=True, default='')

	class Meta:
		indexes = [
			models.Index(fields=['status', '-created_at']),
			models.Index(fields=['reported_user', '-created_at']),
		]


class Waitlister(TimeStampedModel):
	email = models.EmailField(unique=True)
	name = models.CharField(max_length=255, blank=True)
	age = models.IntegerField(null=True, blank=True)
	sex = models.CharField(max_length=10, blank=True)
	country = models.CharField(max_length=100, blank=True)
