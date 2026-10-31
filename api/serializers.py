
from rest_framework import serializers
from drf_spectacular.utils import extend_schema_field

from django.conf import settings
from django.utils import timezone

from urllib.parse import urljoin
from datetime import timedelta

import json
import re


from accounts.models import User
from .models import (
	Profile,
	Goal,
	GoalMembership,
	Partnership,
	Event,
	BuddyRequest,
	Match,
	Task,
	SubTask,
	TimerSession,
	Evidence,
	Notification,
	DevicePushToken,
	Conversation,
	ConversationMembership,
	ContentReport,
	GoalCheckin,
	GoalCheckinBadge,
	GoalCheckinReaction,
	Message,
	Waitlister,
)
from .matching import compatibility_details


class UserSerializer(serializers.ModelSerializer):
	avatar = serializers.SerializerMethodField()

	def get_avatar(self, obj):
		if not getattr(obj, 'avatar', None):
			return None
		try:
			url = obj.avatar.url
		except Exception:
			return None
		if not url:
			return None
		request = self.context.get('request')
		if request is not None:
			return request.build_absolute_uri(url)
		base_url = getattr(settings, 'PUBLIC_BASE_URL', '') or getattr(settings, 'SITE_URL', '')
		if base_url:
			return urljoin(base_url.rstrip('/') + '/', url.lstrip('/'))
		return url

	class Meta:
		model = User
		fields = [
			'id',
			'email',
			'phone',
			'name',
			'avatar',
			'phone_verified',
			'email_verified',
			'preferred_notification_email',
			'preferred_notification_phone',
			'notify_on_new_message',
			'notify_on_new_match',
			'notify_on_reminders',
			'notify_on_milestones',
		]


class PublicUserSerializer(UserSerializer):
	"""Identity fields safe to expose to other Padlupp users."""

	class Meta(UserSerializer.Meta):
		fields = ['id', 'name', 'avatar']


class GoalMemberSerializer(serializers.ModelSerializer):
	id = serializers.IntegerField(source='user_id', read_only=True)
	name = serializers.CharField(source='user.name', read_only=True)
	avatar = serializers.SerializerMethodField()
	is_owner = serializers.SerializerMethodField()
	is_admin = serializers.SerializerMethodField()

	class Meta:
		model = GoalMembership
		fields = ['id', 'name', 'avatar', 'role', 'is_owner', 'is_admin', 'created_at']
		read_only_fields = fields

	def get_avatar(self, obj):
		return PublicUserSerializer(obj.user, context=self.context).data.get('avatar')

	def get_is_owner(self, obj):
		owner_id = self.context.get('owner_id') or obj.goal.user_id
		return obj.user_id == owner_id

	def get_is_admin(self, obj):
		return self.get_is_owner(obj) or obj.role == GoalMembership.ROLE_ADMIN


class NotificationPreferencesSerializer(serializers.ModelSerializer):
	class Meta:
		model = User
		fields = [
			'notify_on_new_message',
			'notify_on_new_match',
			'notify_on_reminders',
			'notify_on_milestones',
		]


class DevicePushTokenRegisterSerializer(serializers.Serializer):
	token = serializers.CharField(max_length=512, trim_whitespace=True)
	platform = serializers.ChoiceField(choices=DevicePushToken.PLATFORM_CHOICES)
	device_id = serializers.CharField(max_length=255, trim_whitespace=True)


class DevicePushTokenUnregisterSerializer(serializers.Serializer):
	token = serializers.CharField(max_length=512, trim_whitespace=True)


class ContentReportRequestSerializer(serializers.Serializer):
	reason = serializers.ChoiceField(choices=ContentReport.REASON_CHOICES)
	details = serializers.CharField(
		required=False,
		allow_blank=True,
		max_length=2000,
		trim_whitespace=True,
	)


class UserUpdateRequestSerializer(serializers.Serializer):
	"""Request body for updating the current user (partial)."""
	name = serializers.CharField(required=False, allow_blank=True)
	phone = serializers.CharField(required=False, allow_blank=True)
	preferred_notification_email = serializers.EmailField(required=False, allow_blank=True)
	preferred_notification_phone = serializers.CharField(required=False, allow_blank=True)


class DeleteAccountRequestSerializer(serializers.Serializer):
	"""Request body for account deletion requests."""
	reason = serializers.CharField(max_length=2000, allow_blank=False, trim_whitespace=True)


class InviteUserRequestSerializer(serializers.Serializer):
	"""Request body for inviting a user by email."""
	email = serializers.EmailField(allow_blank=False)
	name = serializers.CharField(required=False, allow_blank=True, max_length=255)


class InviteUserResponseSerializer(serializers.Serializer):
	detail = serializers.CharField()
	waitlisted = serializers.BooleanField()


class ForgotPasswordRequestOtpSerializer(serializers.Serializer):
	email = serializers.EmailField(allow_blank=False)


class ForgotPasswordVerifyOtpSerializer(serializers.Serializer):
	email = serializers.EmailField(allow_blank=False)
	otp = serializers.CharField(min_length=4, max_length=12, allow_blank=False, trim_whitespace=True)


class ForgotPasswordVerifyOtpResponseSerializer(serializers.Serializer):
	detail = serializers.CharField()
	reset_token = serializers.CharField()


class ForgotPasswordResetPasswordSerializer(serializers.Serializer):
	reset_token = serializers.CharField(allow_blank=False, trim_whitespace=True)
	new_password = serializers.CharField(min_length=6, max_length=128, allow_blank=False, trim_whitespace=False)
	confirm_password = serializers.CharField(min_length=6, max_length=128, allow_blank=False, trim_whitespace=False)

	def validate(self, attrs):
		if attrs.get('new_password') != attrs.get('confirm_password'):
			raise serializers.ValidationError({'confirm_password': 'Passwords do not match.'})
		return attrs


class CommaSeparatedListField(serializers.Field):
	"""Represents a comma-separated string in the DB as a list in the API.

	- DB: "a, b, c" (TextField)
	- API: ["a", "b", "c"]

	Also tolerates a JSON-encoded list string (legacy) like: '["a", "b"]'.
	"""

	def to_representation(self, value):
		if value is None:
			return []
		if isinstance(value, list):
			return [str(v).strip() for v in value if str(v).strip()]
		if not isinstance(value, str):
			return []

		s = value.strip()
		if not s:
			return []
		# Legacy tolerance: if a list was accidentally stored as JSON.
		if s.startswith('[') and s.endswith(']'):
			try:
				decoded = json.loads(s)
				if isinstance(decoded, list):
					return [str(v).strip() for v in decoded if str(v).strip()]
			except Exception:
				pass
		return [part.strip() for part in s.split(',') if part.strip()]

	def to_internal_value(self, data):
		if data is None:
			return None
		if isinstance(data, str):
			# Allow passing comma-separated string directly.
			return data
		if isinstance(data, list):
			items = []
			for item in data:
				if not isinstance(item, str):
					raise serializers.ValidationError('Each interest must be a string.')
				v = item.strip()
				if v:
					items.append(v)
			return ','.join(items)
		raise serializers.ValidationError('Interests must be a list of strings or a comma-separated string.')


class ProfileSerializer(serializers.ModelSerializer):
	user = PublicUserSerializer(read_only=True)
	bio = serializers.CharField(required=False, allow_blank=False, trim_whitespace=True)
	interests = CommaSeparatedListField(required=False)
	compatibility_score = serializers.SerializerMethodField()
	rating = serializers.SerializerMethodField()
	compatibility_reasons = serializers.SerializerMethodField()

	class Meta:
		model = Profile
		fields = [
			'id',
			'user',
			'bio',
			'location',
			'experience',
			'interests',
			'time_zone',
			'focus_areas',
			'availability',
			'communication_styles',
			'created_at',
			'updated_at',
			'compatibility_score',
			'compatibility_reasons',
			'rating',
		]

	@extend_schema_field(serializers.IntegerField(allow_null=True))
	def get_compatibility_score(self, obj):
		source = self.context.get('source_profile')
		if source is None:
			request = self.context.get('request')
			user = getattr(request, 'user', None)
			if user and getattr(user, 'is_authenticated', False):
				source = getattr(user, 'profile', None)
		return compatibility_details(source, obj)['score'] if source else None

	@extend_schema_field(serializers.ListField(child=serializers.CharField()))
	def get_compatibility_reasons(self, obj):
		source = self.context.get('source_profile')
		if source is None:
			request = self.context.get('request')
			user = getattr(request, 'user', None)
			if user and getattr(user, 'is_authenticated', False):
				source = getattr(user, 'profile', None)
		return compatibility_details(source, obj)['reasons'] if source else []
	
	@extend_schema_field(serializers.FloatField(allow_null=True))
	def get_rating(self, obj):
		# Ratings stay empty until real user feedback exists; fabricated values are misleading.
		return None


class UserProfileResponseSerializer(serializers.Serializer):
	"""Response body for endpoints returning both User and Profile."""
	user = UserSerializer(read_only=True)
	profile = ProfileSerializer(read_only=True)

class RegisterRequestSerializer(serializers.Serializer):
	email = serializers.EmailField()
	password = serializers.CharField()
	name = serializers.CharField()
	phone = serializers.CharField(required=False, allow_blank=True)
	referral_token = serializers.UUIDField(required=False, allow_null=True)

class RegisterResponseSerializer(serializers.Serializer):
	user = UserSerializer(read_only=True)  # Should match UserSerializer fields
	token = serializers.CharField()


class LongestStreakResponseSerializer(serializers.Serializer):
	longest_streak_count = serializers.IntegerField()
	current_streak_count = serializers.IntegerField()


class AwardProgressSerializer(serializers.Serializer):
	key = serializers.CharField()
	title = serializers.CharField()
	description = serializers.CharField()
	current = serializers.IntegerField()
	target = serializers.IntegerField()
	unlocked = serializers.BooleanField()
	unlocked_at = serializers.DateTimeField(allow_null=True)


class AwardCategorySerializer(serializers.Serializer):
	key = serializers.CharField()
	title = serializers.CharField()
	awards = AwardProgressSerializer(many=True)


class AwardsResponseSerializer(serializers.Serializer):
	unlocked_count = serializers.IntegerField()
	total_count = serializers.IntegerField()
	categories = AwardCategorySerializer(many=True)





class GoalSerializer(serializers.ModelSerializer):
	user = PublicUserSerializer(read_only=True)
	partnership = serializers.SerializerMethodField(read_only=True)
	members = serializers.SerializerMethodField()
	conversation = serializers.PrimaryKeyRelatedField(queryset=Conversation.objects.all(), required=False, allow_null=True, write_only=True)
	conversation_id = serializers.SerializerMethodField()
	member_count = serializers.SerializerMethodField()
	can_edit = serializers.SerializerMethodField()
	can_manage_members = serializers.SerializerMethodField()
	can_manage_roles = serializers.SerializerMethodField()
	community_task_id = serializers.SerializerMethodField()
	source_group_id = serializers.SerializerMethodField()
	can_checkin = serializers.SerializerMethodField()
	can_write = serializers.SerializerMethodField()
	progress = serializers.SerializerMethodField()
	task_status = serializers.SerializerMethodField()
	membership_state = serializers.SerializerMethodField()

	class Meta:
		model = Goal
		fields = [
			'id',
			'user',
			'partnership',
			'conversation',
			'members',
			'conversation_id',
			'member_count',
			'can_edit',
			'can_manage_members',
			'can_manage_roles',
			'community_task_id', 'source_group_id', 'can_checkin', 'can_write', 'progress', 'task_status', 'membership_state',
			'title',
			'category',
			'importance',
			'checkin_frequency',
			'is_public',
			'is_shared',
			'shared_id',
			'invite_link',
			'description',
			'start_date',
			'start_time',
			'target_date',
			'is_active',
			'status',
			'created_at',
			'updated_at',
		]
		read_only_fields = ['user', 'partnership', 'members', 'conversation_id', 'member_count', 'can_edit', 'can_manage_members', 'can_manage_roles', 'is_shared', 'shared_id', 'invite_link']

	def get_partnership(self, obj):
		return obj.partnership_id if obj.partnership_id else None

	def get_member_count(self, obj):
		return obj.members.count() if hasattr(obj, 'members') else 0

	def get_conversation_id(self, obj):
		conversation = getattr(obj, 'conversation', None)
		return getattr(conversation, 'id', None)

	def get_members(self, obj):
		memberships = obj.goal_memberships.select_related('user').filter(user__deleted=False)
		memberships = sorted(memberships, key=lambda membership: (membership.user_id != obj.user_id, membership.created_at))
		return GoalMemberSerializer(
			memberships,
			many=True,
			context={**self.context, 'owner_id': obj.user_id},
		).data

	def get_can_edit(self, obj):
		request = self.context.get('request')
		user = getattr(request, 'user', None)
		if not user or not getattr(user, 'is_authenticated', False):
			return False
		if getattr(obj, 'community_task', None):
			from .community_access import can_manage_task, can_write_goal
			return can_manage_task(obj.community_task, user) and can_write_goal(obj, user)
		return user.id == obj.user_id or obj.members.filter(id=user.id).exists()

	def get_community_task_id(self, obj):
		return getattr(getattr(obj, 'community_task', None), 'id', None)

	def get_source_group_id(self, obj):
		return getattr(getattr(obj, 'community_task', None), 'group_id', None)

	def get_can_write(self, obj):
		from .community_access import can_write_goal
		return can_write_goal(obj, getattr(self.context.get('request'), 'user', None))

	def get_can_checkin(self, obj):
		from .community_access import task_membership
		user = getattr(self.context.get('request'), 'user', None)
		task = getattr(obj, 'community_task', None)
		membership = task_membership(task, user) if task else None
		return self.get_can_write(obj) and (not task or bool(membership and membership.state == 'active'))

	def get_progress(self, obj):
		task = getattr(obj, 'community_task', None)
		ids = list(task.memberships.filter(state='active', user__is_active=True, user__deleted=False).values_list('user_id', flat=True)) if task else list(obj.members.values_list('id', flat=True))
		if not task and obj.user_id not in ids:
			ids.append(obj.user_id)
		latest = {}
		for checkin in obj.checkins.filter(user_id__in=ids, submitted_at__isnull=False).order_by('user_id', '-submitted_at', '-id'):
			latest.setdefault(checkin.user_id, checkin.completion_percent)
		return round(sum(latest.get(uid, 0) for uid in ids) / len(ids), 2) if ids else 0

	def get_task_status(self, obj):
		return getattr(getattr(obj, 'community_task', None), 'status', obj.status)

	def get_membership_state(self, obj):
		task = getattr(obj, 'community_task', None)
		if not task:
			return None
		from .community_access import task_membership
		membership = task_membership(task, getattr(self.context.get('request'), 'user', None))
		return membership.state if membership else None

	def get_can_manage_members(self, obj):
		request = self.context.get('request')
		user = getattr(request, 'user', None)
		if not user or not getattr(user, 'is_authenticated', False):
			return False
		if getattr(obj, 'community_task', None):
			from .community_access import can_manage_task, can_write_goal
			return can_manage_task(obj.community_task, user) and can_write_goal(obj, user)
		return user.id == obj.user_id or obj.goal_memberships.filter(
			user_id=user.id,
			role=GoalMembership.ROLE_ADMIN,
		).exists()

	def get_can_manage_roles(self, obj):
		request = self.context.get('request')
		user = getattr(request, 'user', None)
		if getattr(obj, 'community_task', None):
			return self.get_can_manage_members(obj)
		return bool(user and getattr(user, 'is_authenticated', False) and user.id == obj.user_id)


class PublicGoalPreviewSerializer(serializers.ModelSerializer):
	owner = serializers.SerializerMethodField()
	member_count = serializers.SerializerMethodField()

	class Meta:
		model = Goal
		fields = [
			'id', 'title', 'category', 'importance', 'checkin_frequency',
			'description', 'start_date', 'target_date', 'status', 'owner', 'member_count',
		]

	def get_owner(self, obj):
		avatar = None
		if getattr(obj.user, 'avatar', None):
			try:
				avatar = obj.user.avatar.url
			except (AttributeError, ValueError):
				pass
		request = self.context.get('request')
		if request and avatar:
			avatar = request.build_absolute_uri(avatar)
		return {'id': obj.user_id, 'name': obj.user.name, 'avatar': avatar}

	def get_member_count(self, obj):
		return obj.members.count()


class GoalJoinRequestSerializer(serializers.Serializer):
	shared_id = serializers.UUIDField()


class GoalJoinResponseSerializer(serializers.Serializer):
	detail = serializers.CharField()
	goal_id = serializers.IntegerField()
	direct_link = serializers.URLField()


class GoalShareRequestSerializer(serializers.Serializer):
	emails = serializers.ListField(child=serializers.EmailField(), allow_empty=False)
	message = serializers.CharField(required=False, allow_blank=True, max_length=4000)


class GoalMemberRoleRequestSerializer(serializers.Serializer):
	role = serializers.ChoiceField(choices=GoalMembership.ROLE_CHOICES)


class GoalLeaveRequestSerializer(serializers.Serializer):
	reason = serializers.ChoiceField(choices=[
		('different_group', 'Found a different group'),
		('interest_mismatch', 'Group does not match my interests'),
		('not_enough_activities', 'Not enough activities'),
		('goals_achieved', 'Goals achieved'),
		('other', 'Other'),
	])
	details = serializers.CharField(required=False, allow_blank=True, max_length=2000, trim_whitespace=True)


class GoalShareResponseSerializer(serializers.Serializer):
	detail = serializers.CharField()
	goal_id = serializers.IntegerField()
	direct_link = serializers.URLField()
	public_share_link = serializers.URLField()
	share_link = serializers.URLField()
	invite_link = serializers.URLField()
	added_user_ids = serializers.ListField(child=serializers.IntegerField())
	invited_emails = serializers.ListField(child=serializers.EmailField())


class BuddyProfileResponseSerializer(serializers.Serializer):
	user = PublicUserSerializer(read_only=True)
	profile = ProfileSerializer(read_only=True)


class PartnershipSerializer(serializers.ModelSerializer):
	class Meta:
		model = Partnership
		fields = [
			'id',
			'user_a',
			'user_b',
			'is_active',
			'paused',
			'focus_goals',
			'created_at',
			'updated_at',
		]
		read_only_fields = fields


class MatchSerializer(serializers.ModelSerializer):
	class Meta:
		model = Match
		fields = [
			'id',
			'from_user',
			'to_user',
			'action',
			'created_at',
			'updated_at',
		]
		read_only_fields = ['from_user']
		validators = []

	def create(self, validated_data):
		match, _ = Match.objects.update_or_create(
			from_user=validated_data['from_user'],
			to_user=validated_data['to_user'],
			defaults={'action': validated_data['action']},
		)
		return match


class CommunityWorkSerializer(serializers.ModelSerializer):
	def validate(self, attrs):
		from .community_access import can_write_goal
		user = getattr(self.context.get('request'), 'user', None)
		task = attrs.get('task', getattr(self.instance, 'task', None))
		goal = attrs.get('goal', getattr(self.instance, 'goal', None)) or getattr(task, 'goal', None)
		original = getattr(self.instance, 'goal', None) or getattr(getattr(self.instance, 'task', None), 'goal', None)
		for candidate in [goal, original]:
			if candidate and getattr(candidate, 'community_task', None) and not can_write_goal(candidate, user):
				from rest_framework.exceptions import PermissionDenied
				raise PermissionDenied('This pod is read-only or you are not an active member.')
		if original and goal and original.pk != goal.pk and (getattr(original, 'community_task', None) or getattr(goal, 'community_task', None)):
			raise serializers.ValidationError('Community pod work cannot be moved to a different goal.')
		return attrs


class TaskSerializer(CommunityWorkSerializer):
	class Meta:
		model = Task
		fields = [
			'id',
			'goal',
			'partnership',
			'owner',
			'title',
			'completed',
			'description',
			'due_at',
			'status',
			'is_shared',
			'is_overdue',
			'created_at',
			'updated_at',
		]
		read_only_fields = ['owner', 'is_overdue']


class SubTaskSerializer(CommunityWorkSerializer):
	class Meta:
		model = SubTask
		fields = [
			'id',
			'task',
			'owner',
			'title',
			'description',
			'due_at',
			'status',
			'created_at',
			'updated_at',
		]
		read_only_fields = ['owner']


class TimerSessionSerializer(serializers.ModelSerializer):
	class Meta:
		model = TimerSession
		fields = [
			'id',
			'task',
			'subtask',
			'user',
			'started_at',
			'ended_at',
			'notes',
			'created_at',
			'updated_at',
		]
		read_only_fields = ['user']


class EvidenceSerializer(CommunityWorkSerializer):
	class Meta:
		model = Evidence
		fields = [
			'id',
			'task',
			'subtask',
			'submitted_by',
			'text',
			'files',
			'links',
			'submitted_at',
			'reviewed_at',
			'approved',
			'reviewer',
			'created_at',
			'updated_at',
		]
		read_only_fields = ['submitted_by', 'submitted_at', 'reviewed_at', 'approved', 'reviewer']


class NotificationSerializer(serializers.ModelSerializer):
	payload = serializers.SerializerMethodField()

	def get_payload(self, obj):
		from .community_messaging import notification_payload
		user = getattr(self.context.get('request'), 'user', None)
		return notification_payload(obj, user) or {}

	class Meta:
		model = Notification
		fields = [
			'id',
			'user',
			'type',
			'payload',
			'is_read',
			'created_at',
			'updated_at',
		]
		read_only_fields = ['user']


class MessageReplySerializer(serializers.ModelSerializer):
	sender = PublicUserSerializer(read_only=True)
	attachment = serializers.SerializerMethodField()

	class Meta:
		model = Message
		fields = ['id', 'sender', 'text', 'attachment', 'attachment_name', 'recalled_at', 'created_at']
		read_only_fields = fields

	def to_representation(self, instance):
		data = super().to_representation(instance)
		if instance.recalled_at:
			data.update({'text': 'This message was removed by a moderator' if instance.deletion_kind == 'moderator' else 'This message was deleted', 'attachment': None, 'attachment_name': ''})
		return data

	def get_attachment(self, obj):
		from .community_messaging import attachment_url
		return attachment_url(obj, self.context.get('request'))


class MessageSerializer(serializers.ModelSerializer):
	sender = PublicUserSerializer(read_only=True)
	reply_to = serializers.SerializerMethodField()
	reply_to_message_id = serializers.PrimaryKeyRelatedField(
		queryset=Message.objects.all(),
		required=False,
		allow_null=True,
		write_only=True,
		source='reply_to_message',
	)
	can_recall = serializers.SerializerMethodField()
	is_recalled = serializers.SerializerMethodField()
	attachment = serializers.FileField(write_only=True, required=False, allow_null=True)
	poll = serializers.JSONField(required=False, write_only=True)
	can_delete_everyone = serializers.SerializerMethodField()
	can_moderate = serializers.SerializerMethodField()
	is_pinned = serializers.SerializerMethodField()
	reactions = serializers.SerializerMethodField()
	can_react = serializers.SerializerMethodField()

	class Meta:
		model = Message
		fields = [
			'id',
			'conversation',
			'sender',
			'text',
			'is_a_reply',
			'reply_to',
			'reply_to_message_id',
			'attachment',
			'attachment_name',
			'attachment_mime',
			'attachment_size',
			'is_read',
			'kind',
			'metadata',
			'recalled_at',
			'is_recalled',
			'can_recall',
			'can_delete_everyone', 'can_moderate', 'is_pinned', 'deletion_kind', 'reactions', 'can_react', 'poll',
			'created_at',
			'updated_at',
		]
		read_only_fields = ['sender', 'is_read', 'attachment_name', 'attachment_mime', 'attachment_size', 'is_a_reply', 'reply_to', 'kind', 'metadata', 'recalled_at', 'is_recalled', 'can_recall', 'deletion_kind']

	def to_representation(self, instance):
		from .community_messaging import attachment_url, safe_file_mime, safe_file_name, visible_messages
		data = super().to_representation(instance)
		data['attachment'] = attachment_url(instance, self.context.get('request'))
		if instance.attachment:
			data['attachment_name'] = safe_file_name(instance.attachment_name or instance.attachment.name)
			data['attachment_mime'] = safe_file_mime(data['attachment_name'], instance.attachment_mime)
		poll = getattr(instance, 'poll', None)
		data['poll'] = None if not poll or instance.recalled_at else {
			'id': poll.pk, 'question': poll.question, 'multiple_answers': poll.multiple_answers,
			'options': [{'id': option.pk, 'text': option.text, 'votes': PublicUserSerializer(
				[v.user for v in option.votes.all()], many=True, context=self.context).data} for option in poll.options.all()],
		}
		user = getattr(self.context.get('request'), 'user', None)
		outside_chat = bool(user and self.context.get('resources') and not visible_messages(Message.objects.filter(pk=instance.pk), user).exists())
		if self.context.get('resources'):
			data['links'] = re.findall(r'https?://[^\s<>"\x27]+', instance.text) if not instance.recalled_at else []
		if outside_chat:
			data.update({'text': '', 'reply_to': None, 'metadata': {}, 'poll': None, 'reactions': [], 'can_react': False})
		if instance.recalled_at:
			data.update({
				'text': 'This message was removed by a moderator' if instance.deletion_kind == 'moderator' else 'This message was deleted',
				'attachment': None,
				'attachment_name': '',
				'attachment_mime': '',
				'attachment_size': None,
				'metadata': {}, 'reply_to': None, 'poll': None, 'reactions': [], 'is_pinned': False,
			})
		return data

	@extend_schema_field(serializers.BooleanField())
	def get_is_recalled(self, obj):
		return bool(obj.recalled_at)

	@extend_schema_field(serializers.BooleanField())
	def get_can_recall(self, obj):
		request = self.context.get('request')
		user = getattr(request, 'user', None)
		from .community_messaging import can_sender_delete
		return can_sender_delete(obj, user)

	def get_can_moderate(self, obj):
		from .community_messaging import can_moderate
		return not obj.recalled_at and can_moderate(obj, getattr(self.context.get('request'), 'user', None))

	def get_can_delete_everyone(self, obj):
		return self.get_can_recall(obj) or self.get_can_moderate(obj)

	def get_is_pinned(self, obj):
		return not obj.recalled_at and hasattr(obj, 'pin')

	def get_reactions(self, obj):
		return [] if obj.recalled_at else [{'emoji': reaction.emoji, 'user': PublicUserSerializer(reaction.user, context=self.context).data} for reaction in obj.reactions.all()]

	@extend_schema_field(serializers.BooleanField())
	def get_can_react(self, obj):
		from .community_messaging import can_interact
		user = getattr(self.context.get('request'), 'user', None)
		return bool(user and user.is_authenticated and not obj.recalled_at and can_interact(obj.conversation, user))

	@extend_schema_field(MessageReplySerializer)
	def get_reply_to(self, obj):
		reply = getattr(obj, 'reply_to_message', None)
		if not reply:
			return None
		from .community_messaging import visible_messages
		user = getattr(self.context.get('request'), 'user', None)
		if not user or not visible_messages(Message.objects.filter(pk=reply.pk), user).exists():
			return None
		return MessageReplySerializer(reply, context=self.context).data

	def create(self, validated_data):
		from .message_models import MessagePoll, MessagePollOption
		poll_data = validated_data.pop('poll', None)
		attachment = validated_data.get('attachment')
		if attachment:
			validated_data.update(attachment_name=attachment.name, attachment_size=attachment.size,
				attachment_mime=getattr(attachment, 'content_type', '') or 'application/octet-stream')
		reply_to = validated_data.get('reply_to_message')
		validated_data['is_a_reply'] = bool(reply_to)
		message = super().create(validated_data)
		if poll_data:
			poll = MessagePoll.objects.create(message=message, question=poll_data['question'], multiple_answers=poll_data.get('multiple_answers', False))
			MessagePollOption.objects.bulk_create([MessagePollOption(poll=poll, text=text, position=i) for i, text in enumerate(poll_data['options'])])
		return message

	def validate(self, attrs):
		from .community_messaging import assert_post_allowed, visible_messages
		reply_to = attrs.get('reply_to_message')
		conversation = attrs.get('conversation')
		if reply_to and conversation and reply_to.conversation_id != conversation.id:
			raise serializers.ValidationError({'reply_to_message_id': 'Reply message must belong to the same conversation.'})
		user = getattr(self.context.get('request'), 'user', None)
		if reply_to and user and not visible_messages(Message.objects.filter(pk=reply_to.pk), user).exists():
			raise serializers.ValidationError({'reply_to_message_id': 'Reply target is not accessible.'})
		poll = attrs.get('poll')
		if isinstance(poll, str):
			try:
				poll = attrs['poll'] = json.loads(poll)
			except ValueError:
				raise serializers.ValidationError({'poll': 'Invalid poll.'})
		if poll is not None:
			if not isinstance(poll, dict) or not isinstance(poll.get('question'), str) or not poll['question'].strip() or len(poll['question']) > 500:
				raise serializers.ValidationError({'poll': 'A poll question is required (maximum 500 characters).'})
			options = poll.get('options')
			if not isinstance(options, list) or not 2 <= len(options) <= 12 or any(not isinstance(o, str) or not o.strip() or len(o) > 255 for o in options):
				raise serializers.ValidationError({'poll': 'Supply 2 to 12 non-empty options of at most 255 characters.'})
			if type(poll.get('multiple_answers', False)) is not bool:
				raise serializers.ValidationError({'poll': 'multiple_answers must be a boolean.'})
		if not attrs.get('text', '').strip() and not attrs.get('attachment') and not poll:
			raise serializers.ValidationError('A message needs text, an attachment or a poll.')
		attachment = attrs.get('attachment')
		if attachment and attachment.size > int(getattr(settings, 'CHAT_UPLOAD_MAX_BYTES', 25 * 1024 * 1024)):
			raise serializers.ValidationError({'attachment': 'The file exceeds the upload limit.'})
		if conversation and user:
			assert_post_allowed(conversation, user, attrs.get('text', ''), attachment, poll)
		return attrs


class ConversationMemberSerializer(serializers.ModelSerializer):
	user = PublicUserSerializer(read_only=True)

	class Meta:
		model = ConversationMembership
		fields = ['id', 'user', 'created_at']
		read_only_fields = fields


class ConversationMediaSerializer(serializers.ModelSerializer):
	file = serializers.SerializerMethodField()
	sender_id = serializers.IntegerField(read_only=True)
	sender_name = serializers.CharField(source='sender.name', read_only=True)

	class Meta:
		model = Message
		fields = [
			'id',
			'file',
			'attachment_name',
			'attachment_mime',
			'attachment_size',
			'created_at',
			'sender_id',
			'sender_name',
		]
		read_only_fields = fields

	def to_representation(self, instance):
		from .community_messaging import safe_file_mime, safe_file_name
		data = super().to_representation(instance)
		data['attachment_name'] = safe_file_name(instance.attachment_name or instance.attachment.name)
		data['attachment_mime'] = safe_file_mime(data['attachment_name'], instance.attachment_mime)
		return data

	@extend_schema_field(serializers.URLField(allow_null=True))
	def get_file(self, obj):
		from .community_messaging import attachment_url
		return attachment_url(obj, self.context.get('request'))


class ConversationRenameRequestSerializer(serializers.Serializer):
	name = serializers.CharField(max_length=255, allow_blank=False, trim_whitespace=True)


class ConversationSerializer(serializers.ModelSerializer):
	last_message = serializers.SerializerMethodField()
	unread_count = serializers.SerializerMethodField()
	goal = serializers.PrimaryKeyRelatedField(read_only=True)
	name = serializers.CharField(read_only=True)
	is_group = serializers.BooleanField(read_only=True)
	members = serializers.SerializerMethodField()
	archived_at = serializers.SerializerMethodField()
	is_archived = serializers.SerializerMethodField()

	class Meta:
		model = Conversation
		fields = [
			'id',
			'partnership',
			'goal',
			'name',
			'is_group',
			'members',
			'last_message',
			'unread_count',
			'archived_at',
			'is_archived',
			'created_at',
			'updated_at',
		]

	@extend_schema_field(MessageSerializer)
	def get_last_message(self, obj):
		from .community_messaging import visible_messages
		user = getattr(self.context.get('request'), 'user', None)
		message = visible_messages(obj.messages.all(), user).order_by('-created_at', '-id').first() if user else None
		return MessageSerializer(message, context=self.context).data if message else None

	def get_members(self, obj):
		if obj.goal_id:
			memberships = obj.goal.goal_memberships.select_related('user').filter(user__deleted=False)
			memberships = sorted(memberships, key=lambda membership: (membership.user_id != obj.goal.user_id, membership.created_at))
			return GoalMemberSerializer(
				memberships,
				many=True,
				context={**self.context, 'owner_id': obj.goal.user_id},
			).data
		return PublicUserSerializer(obj.members.all(), many=True, context=self.context).data

	@extend_schema_field(serializers.IntegerField())
	def get_unread_count(self, obj):
		request = self.context.get('request')
		user = getattr(request, 'user', None)
		if not user or not getattr(user, 'is_authenticated', False):
			return 0
		from .community_messaging import visible_messages
		return visible_messages(obj.messages.filter(is_read=False).exclude(sender=user), user).count()

	def _membership(self, obj):
		request = self.context.get('request')
		user = getattr(request, 'user', None)
		if not user or not getattr(user, 'is_authenticated', False):
			return None
		return obj.conversation_memberships.filter(user=user).first()

	@extend_schema_field(serializers.DateTimeField(allow_null=True))
	def get_archived_at(self, obj):
		membership = self._membership(obj)
		return membership.archived_at if membership else None

	@extend_schema_field(serializers.BooleanField())
	def get_is_archived(self, obj):
		return bool(self.get_archived_at(obj))


class GoalCheckinReactionSerializer(serializers.ModelSerializer):
	user = PublicUserSerializer(read_only=True)

	class Meta:
		model = GoalCheckinReaction
		fields = ['id', 'user', 'reaction', 'created_at']
		read_only_fields = ['id', 'user', 'created_at']


class GoalCheckinSerializer(serializers.ModelSerializer):
	user = PublicUserSerializer(read_only=True)
	goal_title = serializers.CharField(source='goal.title', read_only=True)
	evidence_url = serializers.SerializerMethodField()
	evidence_name = serializers.SerializerMethodField()
	evidence_mime = serializers.SerializerMethodField()
	reactions = GoalCheckinReactionSerializer(many=True, read_only=True)
	has_badge = serializers.SerializerMethodField()
	reviewer = PublicUserSerializer(read_only=True)
	can_review = serializers.SerializerMethodField()

	class Meta:
		model = GoalCheckin
		fields = [
			'id', 'goal', 'goal_title', 'user', 'scheduled_for', 'status',
			'completion_percent', 'update_text', 'blocker', 'evidence',
			'mood', 'next_focus', 'review_status', 'reviewer', 'reviewed_at', 'can_review', 'evidence_deleted_at',
			'evidence_url', 'evidence_name', 'evidence_mime', 'evidence_view_once', 'evidence_expires_at',
			'submitted_at', 'reactions', 'has_badge', 'created_at', 'updated_at',
		]
		read_only_fields = [
			'user', 'evidence_url', 'evidence_name', 'evidence_mime', 'evidence_expires_at', 'submitted_at',
			'reactions', 'has_badge',
			'review_status', 'reviewer', 'reviewed_at', 'evidence_deleted_at', 'evidence_view_once',
		]
		extra_kwargs = {'evidence': {'write_only': True, 'required': False, 'allow_null': True}}

	def validate_status(self, value):
		if value in {GoalCheckin.STATUS_PENDING, GoalCheckin.STATUS_MISSED}:
			raise serializers.ValidationError('Submit completed, partial, or blocked as your check-in status.')
		return value

	def validate(self, attrs):
		status_value = attrs.get('status', getattr(self.instance, 'status', None))
		completion = attrs.get('completion_percent', getattr(self.instance, 'completion_percent', 0))
		blocker = (attrs.get('blocker', getattr(self.instance, 'blocker', '')) or '').strip()
		scheduled_for = attrs.get('scheduled_for', getattr(self.instance, 'scheduled_for', None))
		if scheduled_for and scheduled_for > timezone.localdate():
			raise serializers.ValidationError({'scheduled_for': 'You cannot submit a future check-in.'})
		if status_value == GoalCheckin.STATUS_COMPLETED and completion != 100:
			raise serializers.ValidationError({'completion_percent': 'Completed check-ins must be 100%.'})
		if status_value == GoalCheckin.STATUS_BLOCKED and not blocker:
			raise serializers.ValidationError({'blocker': 'Describe what is blocking you.'})
		goal = attrs.get('goal', getattr(self.instance, 'goal', None))
		if self.instance and (goal.pk != self.instance.goal_id or scheduled_for != self.instance.scheduled_for):
			raise serializers.ValidationError('The scheduled goal and cycle cannot be changed.')
		if goal and getattr(goal, 'community_task', None):
			evidence = attrs.get('evidence', getattr(self.instance, 'evidence', None))
			if not evidence:
				raise serializers.ValidationError({'evidence': 'Evidence is required for a pod check-in.'})
			for name in ['mood', 'update_text', 'next_focus']:
				if not (attrs.get(name, getattr(self.instance, name, '')) or '').strip():
					raise serializers.ValidationError({name: 'This field is required.'})
		evidence = attrs.get('evidence')
		if evidence and evidence.size > 15 * 1024 * 1024:
			raise serializers.ValidationError({'evidence': 'Evidence must be no larger than 15 MB.'})
		return attrs

	def to_representation(self, instance):
		data = super().to_representation(instance)
		# Legacy stored flags are not an active product policy, even before backfill.
		data['evidence_view_once'] = False
		data['evidence_expires_at'] = None
		return data

	@extend_schema_field(serializers.URLField(allow_null=True))
	def get_evidence_url(self, obj):
		if not obj.evidence:
			return None
		request = self.context.get('request')
		path = f'/api-v1/checkins/{obj.id}/evidence/'
		return request.build_absolute_uri(path) if request else path

	@extend_schema_field(serializers.CharField(allow_null=True))
	def get_evidence_name(self, obj):
		from .community_messaging import safe_file_name
		return safe_file_name(obj.evidence.name) if obj.evidence else None

	@extend_schema_field(serializers.CharField(allow_null=True))
	def get_evidence_mime(self, obj):
		from .community_messaging import safe_file_mime
		return safe_file_mime(self.get_evidence_name(obj)) if obj.evidence else None

	@extend_schema_field(serializers.BooleanField())
	def get_can_review(self, obj):
		from .community_messaging import can_review_checkin
		return can_review_checkin(obj, getattr(self.context.get('request'), 'user', None))

	@extend_schema_field(serializers.BooleanField())
	def get_has_badge(self, obj):
		return GoalCheckinBadge.objects.filter(goal=obj.goal, scheduled_for=obj.scheduled_for).exists()


class GoalCheckinReactionRequestSerializer(serializers.Serializer):
	reaction = serializers.ChoiceField(choices=GoalCheckinReaction.REACTION_CHOICES)


class WaitlisterSerializer(serializers.ModelSerializer):
	class Meta:
		model = Waitlister
		fields = [
			'id',
			'email',
			'name',
			'age',
			'sex',
			'country',
			'created_at',
			'updated_at',
		]

	def validate_email(self, value):
		# Normalize to lower-case to avoid case-sensitive duplicates
		email = value.lower()
		if Waitlister.objects.filter(email__iexact=email).exists():
			raise serializers.ValidationError("This email is already on the waitlist.")
		return value


class EventxSerializer(serializers.ModelSerializer):
	creator = PublicUserSerializer(read_only=True)
	participants = PublicUserSerializer(read_only=True, many=True)
	participants_ids = serializers.PrimaryKeyRelatedField(
		queryset=User.objects.all(),
		many=True,
		required=False,
		write_only=True,
		source='participants',
	)

	class Meta:
		model = Event
		fields = [
			'id',
			'title',
			'description',
			'start_date',
			'start_time',
			'end_date',
			'end_time',
			'banner',
			'event_link',
			'reminder_sent',
			'creator',
			'participants',
			'participants_ids',
			'created_at',
			'updated_at',
		]
		read_only_fields = ['creator', 'participants', 'reminder_sent']


class BuddyFinderProfileSerializer(ProfileSerializer):
	"""Profile serializer used by buddy finder endpoint.

	Adds a computed connection status from the current user to the profile's user.
	"""
	connection_status = serializers.SerializerMethodField()
	buddy_request_id = serializers.SerializerMethodField()
	pending_direction = serializers.SerializerMethodField()
	last_active_at = serializers.DateTimeField(read_only=True, allow_null=True)

	class Meta(ProfileSerializer.Meta):
		fields = ProfileSerializer.Meta.fields + ['connection_status', 'buddy_request_id', 'pending_direction', 'last_active_at']

	@extend_schema_field(serializers.CharField())
	def get_connection_status(self, obj):
		if obj.user_id in self.context.get('connected_user_ids', set()):
			return 'connected'
		return 'pending' if obj.user_id in self.context.get('pending_requests', {}) else 'none'

	@extend_schema_field(serializers.IntegerField(allow_null=True))
	def get_buddy_request_id(self, obj):
		if self.get_connection_status(obj) != 'pending':
			return None
		return self.context['pending_requests'][obj.user_id]['id']

	@extend_schema_field(serializers.ChoiceField(choices=['incoming', 'outgoing'], allow_null=True))
	def get_pending_direction(self, obj):
		if self.get_connection_status(obj) != 'pending':
			return None
		return self.context['pending_requests'][obj.user_id]['direction']
	
class BuddyConnectSerializer(serializers.Serializer):
	to_user = serializers.PrimaryKeyRelatedField(queryset=User.objects.filter(is_active=True, deleted=False))
	message = serializers.CharField(required=False, allow_blank=True, max_length=2000)


class BuddyRequestSerializer(serializers.ModelSerializer):
	from_user = PublicUserSerializer(read_only=True)
	to_user = PublicUserSerializer(read_only=True)

	class Meta:
		model = BuddyRequest
		fields = [
			'id',
			'from_user',
			'to_user',
			'status',
			'message',
			'responded_at',
			'created_at',
			'updated_at',
		]
		read_only_fields = fields


class BuddyConnectionSerializer(serializers.Serializer):
	"""Represents a buddy connection as the other user's profile."""
	user = PublicUserSerializer(read_only=True)
	profile = ProfileSerializer(read_only=True)


class BuddyRequestActionResponseSerializer(serializers.Serializer):
	"""Generic response for buddy request actions (accept/reject).

	- `detail`: human-readable status message.
	- `partnership_id`: present only for the accept action.
	"""
	detail = serializers.CharField()
	partnership_id = serializers.IntegerField(required=False)


class DetailResponseSerializer(serializers.Serializer):
	"""Simple detail message wrapper used for error/success responses."""
	detail = serializers.CharField()


class UserAvatarRequestSerializer(serializers.Serializer):
	"""Request body for updating the user's avatar."""
	avatar = serializers.ImageField()


class ProfileExperienceRequestSerializer(serializers.Serializer):
	"""Partial onboarding fields; omitted values must leave existing data intact."""
	experience = serializers.CharField(required=False, allow_blank=True, allow_null=True)
	interests = CommaSeparatedListField(required=False, allow_null=True)
	bio = serializers.CharField(required=False, allow_blank=False, trim_whitespace=True)


class TaskRequestChangesRequestSerializer(serializers.Serializer):
	"""Request body for task changes request comment."""
	comment = serializers.CharField(required=False, allow_blank=True)


class NotificationMarkAllReadResponseSerializer(serializers.Serializer):
	"""Response body for mark_all_read endpoint."""
	marked_read = serializers.IntegerField()

class LoginRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

class LoginResponseSerializer(serializers.Serializer):
    user = UserSerializer(read_only=True)  # Should match UserSerializer fields
    token = serializers.CharField()


class GoogleAuthRequestSerializer(serializers.Serializer):
	"""Request body for Google sign-in/sign-up.

	Clients should send a Google `id_token` obtained via Google Sign-In.
	"""
	id_token = serializers.CharField()
	# Optional overrides/extra fields (Google does not provide phone)
	name = serializers.CharField(required=False, allow_blank=True)
	phone = serializers.CharField(required=False, allow_blank=True)
	referral_token = serializers.UUIDField(required=False, allow_null=True)


class GoogleAuthResponseSerializer(serializers.Serializer):
	user = UserSerializer(read_only=True)
	token = serializers.CharField()

class LogoutResponseSerializer(serializers.Serializer):
    detail = serializers.CharField()
