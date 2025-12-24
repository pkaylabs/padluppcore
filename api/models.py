from django.conf import settings
from django.db import models

from padluppcore.utils.models import TimeStampedModel


class Profile(TimeStampedModel):
	user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='profile')
	bio = models.TextField(blank=True)
	experience = models.TextField(blank=True)
	subexperience = models.TextField(blank=True, null=True, help_text='additional experience added as comma separated values')
	location = models.CharField(max_length=255, blank=True)
	time_zone = models.CharField(max_length=100, blank=True)
	focus_areas = models.JSONField(default=list, blank=True)
	availability = models.JSONField(default=dict, blank=True)
	communication_styles = models.JSONField(default=list, blank=True)


class Goal(TimeStampedModel):
	user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='goals')
	title = models.CharField(max_length=255)
	description = models.TextField(blank=True)
	start_date = models.DateField(null=True, blank=True)
	target_date = models.DateField(null=True, blank=True)
	is_active = models.BooleanField(default=True)


class Partnership(TimeStampedModel):
	user_a = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='partnerships_as_a')
	user_b = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='partnerships_as_b')
	is_active = models.BooleanField(default=True)
	paused = models.BooleanField(default=False)
	focus_goals = models.ManyToManyField(Goal, related_name='partnerships', blank=True)

	class Meta:
		unique_together = ('user_a', 'user_b')


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


class Conversation(TimeStampedModel):
	partnership = models.OneToOneField(Partnership, on_delete=models.CASCADE, related_name='conversation')


class Message(TimeStampedModel):
	conversation = models.ForeignKey(Conversation, on_delete=models.CASCADE, related_name='messages')
	sender = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='messages')
	text = models.TextField()
	is_read = models.BooleanField(default=False)


class Waitlister(TimeStampedModel):
	email = models.EmailField(unique=True)
	name = models.CharField(max_length=255, blank=True)
	age = models.IntegerField(null=True, blank=True)
	sex = models.CharField(max_length=10, blank=True)
	country = models.CharField(max_length=100, blank=True)