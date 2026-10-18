"""Community groups and their task/pod associations, separate from legacy goals."""
import uuid
import os

from django.conf import settings
from django.db import models
from django.utils import timezone

from padluppcore.utils.models import TimeStampedModel
from .message_models import protected_storage


def standard_rules():
    return [
        'Be respectful and supportive. Harassment and discrimination are not allowed.',
        'Keep discussions relevant, honest and safe. Do not share private information.',
        'Keep accountability and task collaboration on Padlupp.',
    ]


def standard_post_permissions():
    return dict.fromkeys(('text', 'link', 'image', 'video', 'document', 'poll', 'task'), True)


def task_cover_path(instance, filename):
    return f'community_task_covers/{uuid.uuid4().hex}{os.path.splitext(filename)[1].lower()[:16]}'


class CommunityCategory(TimeStampedModel):
    name = models.CharField(max_length=100, unique=True)
    position = models.PositiveSmallIntegerField(default=0)

    class Meta:
        ordering = ['position', 'name']


class CommunityCreatorApproval(TimeStampedModel):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='community_creator_approval')
    approved = models.BooleanField(default=True)
    approved_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='+')


class CommunityGroup(TimeStampedModel):
    creator = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name='created_community_groups')
    category = models.ForeignKey(CommunityCategory, on_delete=models.PROTECT, related_name='groups')
    conversation = models.OneToOneField('api.Conversation', on_delete=models.PROTECT, related_name='community_group')
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    image = models.ImageField(upload_to='community_images/', blank=True, null=True)
    visibility = models.CharField(max_length=12, choices=[('public', 'Public'), ('private', 'Private')], default='public')
    status = models.CharField(max_length=12, choices=[(s, s.title()) for s in ('active', 'archived', 'frozen', 'disabled', 'deleted')], default='active')
    rules = models.JSONField(default=standard_rules)
    post_permissions = models.JSONField(default=standard_post_permissions)


class CommunityMembership(TimeStampedModel):
    group = models.ForeignKey(CommunityGroup, on_delete=models.CASCADE, related_name='memberships')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='community_memberships')
    role = models.CharField(max_length=12, choices=[(r, r.title()) for r in ('admin', 'moderator', 'member')], default='member')
    state = models.CharField(max_length=12, choices=[(s, s.title()) for s in ('active', 'pending', 'left', 'removed', 'banned', 'rejected')], default='pending')
    joined_at = models.DateTimeField(null=True, blank=True)
    left_at = models.DateTimeField(null=True, blank=True)
    muted_until = models.DateTimeField(null=True, blank=True)
    notifications_muted = models.BooleanField(default=False)
    reason = models.TextField(blank=True)
    feedback = models.TextField(blank=True)
    misconduct = models.BooleanField(default=False)

    class Meta:
        constraints = [models.UniqueConstraint(fields=['group', 'user'], name='uniq_community_group_user')]
        indexes = [models.Index(fields=['user', 'state'])]


class CommunityMembershipPeriod(TimeStampedModel):
    membership = models.ForeignKey(CommunityMembership, on_delete=models.CASCADE, related_name='periods')
    joined_at = models.DateTimeField(default=timezone.now)
    ended_at = models.DateTimeField(null=True, blank=True)


class CommunityInvite(TimeStampedModel):
    group = models.ForeignKey(CommunityGroup, on_delete=models.CASCADE, related_name='invitations')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True, related_name='community_invitations')
    invited_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='+')
    role = models.CharField(max_length=12, default='member')
    token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    expires_at = models.DateTimeField()
    status = models.CharField(max_length=12, default='pending')


class CommunityTask(TimeStampedModel):
    group = models.ForeignKey(CommunityGroup, on_delete=models.PROTECT, related_name='community_tasks')
    goal = models.OneToOneField('api.Goal', on_delete=models.PROTECT, related_name='community_task')
    creator = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name='created_community_tasks')
    idempotency_key = models.CharField(max_length=100)
    invite_token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    invitation_deadline = models.DateTimeField()
    member_limit = models.PositiveIntegerField(default=8)
    visibility = models.CharField(max_length=12, choices=[('public', 'Public'), ('private', 'Private')], default='public')
    approval_required = models.BooleanField(default=False)
    enrollment_closed = models.BooleanField(default=False)
    status = models.CharField(max_length=16, default='active')
    custom_interval_days = models.PositiveSmallIntegerField(null=True, blank=True)
    checkin_schedule_effective_from = models.DateField(null=True, blank=True)
    cover = models.FileField(upload_to=task_cover_path, storage=protected_storage, blank=True, null=True)
    limits_approved_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
    limits_approval_reason = models.TextField(blank=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=['creator', 'idempotency_key'], name='uniq_community_task_retry')]


class CommunityTaskMembership(TimeStampedModel):
    task = models.ForeignKey(CommunityTask, on_delete=models.CASCADE, related_name='memberships')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='community_task_memberships')
    role = models.CharField(max_length=12, default='member')
    state = models.CharField(max_length=12, default='pending')
    joined_at = models.DateTimeField(null=True, blank=True)
    left_at = models.DateTimeField(null=True, blank=True)
    reason = models.TextField(blank=True)
    feedback = models.TextField(blank=True)
    link_approval_required = models.BooleanField(default=False)

    class Meta:
        constraints = [models.UniqueConstraint(fields=['task', 'user'], name='uniq_community_task_user')]


class CommunityTaskPeriod(TimeStampedModel):
    membership = models.ForeignKey(CommunityTaskMembership, on_delete=models.CASCADE, related_name='periods')
    joined_at = models.DateTimeField(default=timezone.now)
    ended_at = models.DateTimeField(null=True, blank=True)


class CommunityTaskInvitation(TimeStampedModel):
    task = models.ForeignKey(CommunityTask, on_delete=models.CASCADE, related_name='invitations')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='community_task_invitations')
    invited_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='+')
    status = models.CharField(max_length=12, default='pending')

    class Meta:
        constraints = [models.UniqueConstraint(fields=['task', 'user'], name='uniq_community_task_invite')]


class CommunityAudit(TimeStampedModel):
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='+')
    group = models.ForeignKey(CommunityGroup, on_delete=models.SET_NULL, null=True, blank=True, related_name='audit')
    task = models.ForeignKey(CommunityTask, on_delete=models.SET_NULL, null=True, blank=True, related_name='audit')
    action = models.CharField(max_length=80)
    target_type = models.CharField(max_length=40, blank=True)
    target_id = models.CharField(max_length=100, blank=True)
    reason = models.TextField(blank=True)
    outcome = models.JSONField(default=dict)

    class Meta:
        ordering = ['-created_at', '-id']


class CommunityReport(TimeStampedModel):
    reporter = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='+')
    group = models.ForeignKey(CommunityGroup, on_delete=models.SET_NULL, null=True, blank=True, related_name='reports')
    task = models.ForeignKey(CommunityTask, on_delete=models.SET_NULL, null=True, blank=True, related_name='reports')
    message = models.ForeignKey('api.Message', on_delete=models.SET_NULL, null=True, blank=True, related_name='community_reports')
    reported_user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
    content_report = models.OneToOneField('api.ContentReport', on_delete=models.SET_NULL, null=True, blank=True, related_name='community_report')
    reason = models.CharField(max_length=255)
    details = models.TextField(blank=True)
    status = models.CharField(max_length=20, default='pending')
    reviewer = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
    reviewed_at = models.DateTimeField(null=True, blank=True)
    notes = models.TextField(blank=True)


class CommunityInactivityReview(TimeStampedModel):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='+')
    group = models.ForeignKey(CommunityGroup, on_delete=models.CASCADE, null=True, blank=True, related_name='inactivity_reviews')
    task = models.ForeignKey(CommunityTask, on_delete=models.CASCADE, null=True, blank=True, related_name='inactivity_reviews')
    last_login_at = models.DateTimeField()
    resolved = models.BooleanField(default=False)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['user', 'group', 'last_login_at'], name='uniq_group_inactivity_span'),
            models.UniqueConstraint(fields=['user', 'task', 'last_login_at'], name='uniq_pod_inactivity_span'),
        ]
