
from rest_framework import serializers
from drf_spectacular.utils import extend_schema_field

from django.conf import settings
from django.utils import timezone

from urllib.parse import urljoin
from datetime import timedelta

import json


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
		]


class PublicUserSerializer(UserSerializer):
	"""Identity fields safe to expose to other Padlupp users."""

	class Meta(UserSerializer.Meta):
		fields = ['id', 'name', 'avatar']


class NotificationPreferencesSerializer(serializers.ModelSerializer):
	class Meta:
		model = User
		fields = [
			'notify_on_new_message',
			'notify_on_new_match',
			'notify_on_reminders',
		]


class DevicePushTokenRegisterSerializer(serializers.Serializer):
	token = serializers.CharField(max_length=512, trim_whitespace=True)
	platform = serializers.ChoiceField(choices=DevicePushToken.PLATFORM_CHOICES)
	device_id = serializers.CharField(max_length=255, trim_whitespace=True)


class DevicePushTokenUnregisterSerializer(serializers.Serializer):
	token = serializers.CharField(max_length=512, trim_whitespace=True)


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

class RegisterResponseSerializer(serializers.Serializer):
	user = UserSerializer(read_only=True)  # Should match UserSerializer fields
	token = serializers.CharField()


class LongestStreakResponseSerializer(serializers.Serializer):
	longest_streak_count = serializers.IntegerField()
	current_streak_count = serializers.IntegerField()





class GoalSerializer(serializers.ModelSerializer):
	user = PublicUserSerializer(read_only=True)
	partnership = serializers.SerializerMethodField(read_only=True)
	members = PublicUserSerializer(many=True, read_only=True)
	conversation = serializers.PrimaryKeyRelatedField(queryset=Conversation.objects.all(), required=False, allow_null=True, write_only=True)
	member_count = serializers.SerializerMethodField()
	can_edit = serializers.SerializerMethodField()

	class Meta:
		model = Goal
		fields = [
			'id',
			'user',
			'partnership',
			'conversation',
			'members',
			'member_count',
			'can_edit',
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
		read_only_fields = ['user', 'partnership', 'members', 'member_count', 'can_edit', 'is_shared', 'shared_id', 'invite_link']

	def get_partnership(self, obj):
		return obj.partnership_id if obj.partnership_id else None

	def get_member_count(self, obj):
		return obj.members.count() if hasattr(obj, 'members') else 0

	def get_can_edit(self, obj):
		request = self.context.get('request')
		user = getattr(request, 'user', None)
		if not user or not getattr(user, 'is_authenticated', False):
			return False
		return user.id == obj.user_id or obj.members.filter(id=user.id).exists()


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


class TaskSerializer(serializers.ModelSerializer):
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


class SubTaskSerializer(serializers.ModelSerializer):
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


class EvidenceSerializer(serializers.ModelSerializer):
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

	class Meta:
		model = Message
		fields = ['id', 'sender', 'text', 'attachment', 'attachment_name', 'recalled_at', 'created_at']
		read_only_fields = fields

	def to_representation(self, instance):
		data = super().to_representation(instance)
		if instance.recalled_at:
			data.update({'text': '', 'attachment': None, 'attachment_name': ''})
		return data


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
			'created_at',
			'updated_at',
		]
		read_only_fields = ['sender', 'is_read', 'attachment', 'attachment_name', 'attachment_mime', 'attachment_size', 'is_a_reply', 'reply_to', 'kind', 'metadata', 'recalled_at', 'is_recalled', 'can_recall']

	def to_representation(self, instance):
		data = super().to_representation(instance)
		if instance.recalled_at:
			data.update({
				'text': '',
				'attachment': None,
				'attachment_name': '',
				'attachment_mime': '',
				'attachment_size': None,
			})
		return data

	@extend_schema_field(serializers.BooleanField())
	def get_is_recalled(self, obj):
		return bool(obj.recalled_at)

	@extend_schema_field(serializers.BooleanField())
	def get_can_recall(self, obj):
		request = self.context.get('request')
		user = getattr(request, 'user', None)
		window = int(getattr(settings, 'MESSAGE_RECALL_WINDOW_MINUTES', 15))
		return bool(
			user and getattr(user, 'is_authenticated', False)
			and obj.sender_id == user.id
			and obj.kind == Message.KIND_USER
			and not obj.recalled_at
			and obj.created_at >= timezone.now() - timedelta(minutes=window)
		)

	@extend_schema_field(MessageReplySerializer)
	def get_reply_to(self, obj):
		reply = getattr(obj, 'reply_to_message', None)
		if not reply:
			return None
		return MessageReplySerializer(reply, context=self.context).data

	def create(self, validated_data):
		reply_to = validated_data.get('reply_to_message')
		validated_data['is_a_reply'] = bool(reply_to)
		return super().create(validated_data)

	def validate(self, attrs):
		reply_to = attrs.get('reply_to_message')
		conversation = attrs.get('conversation')
		if reply_to and conversation and reply_to.conversation_id != conversation.id:
			raise serializers.ValidationError({'reply_to_message_id': 'Reply message must belong to the same conversation.'})
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
		fields = ['id', 'file', 'created_at', 'sender_id', 'sender_name']
		read_only_fields = fields

	@extend_schema_field(serializers.URLField(allow_null=True))
	def get_file(self, obj):
		attachment = getattr(obj, 'attachment', None)
		if not attachment:
			return None
		try:
			url = attachment.url
		except Exception:
			return None
		request = self.context.get('request')
		if request is not None:
			return request.build_absolute_uri(url)
		base_url = getattr(settings, 'PUBLIC_BASE_URL', '') or getattr(settings, 'SITE_URL', '')
		if base_url:
			return urljoin(base_url.rstrip('/') + '/', url.lstrip('/'))
		return url


class ConversationRenameRequestSerializer(serializers.Serializer):
	name = serializers.CharField(max_length=255, allow_blank=False, trim_whitespace=True)


class ConversationSerializer(serializers.ModelSerializer):
	last_message = serializers.SerializerMethodField()
	unread_count = serializers.SerializerMethodField()
	goal = serializers.PrimaryKeyRelatedField(read_only=True)
	name = serializers.CharField(read_only=True)
	is_group = serializers.BooleanField(read_only=True)
	members = PublicUserSerializer(many=True, read_only=True)
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
		message = obj.messages.order_by('-created_at').first()
		return MessageSerializer(message, context=self.context).data if message else None

	@extend_schema_field(serializers.IntegerField())
	def get_unread_count(self, obj):
		# Prefer queryset annotation if present.
		annotated = getattr(obj, 'unread_count', None)
		if annotated is not None:
			return int(annotated)
		request = self.context.get('request')
		user = getattr(request, 'user', None)
		if not user or not getattr(user, 'is_authenticated', False):
			return 0
		return obj.messages.filter(is_read=False).exclude(sender=user).count()

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
	reactions = GoalCheckinReactionSerializer(many=True, read_only=True)
	has_badge = serializers.SerializerMethodField()

	class Meta:
		model = GoalCheckin
		fields = [
			'id', 'goal', 'goal_title', 'user', 'scheduled_for', 'status',
			'completion_percent', 'update_text', 'blocker', 'evidence',
			'evidence_url', 'evidence_view_once', 'evidence_expires_at',
			'submitted_at', 'reactions', 'has_badge', 'created_at', 'updated_at',
		]
		read_only_fields = [
			'user', 'evidence_url', 'evidence_expires_at', 'submitted_at',
			'reactions', 'has_badge',
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
		return attrs

	@extend_schema_field(serializers.URLField(allow_null=True))
	def get_evidence_url(self, obj):
		if not obj.evidence:
			return None
		request = self.context.get('request')
		path = f'/api-v1/checkins/{obj.id}/evidence/'
		return request.build_absolute_uri(path) if request else path

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

	class Meta(ProfileSerializer.Meta):
		fields = ProfileSerializer.Meta.fields + ['connection_status', 'buddy_request_id']

	@extend_schema_field(serializers.CharField())
	def get_connection_status(self, obj):
		pending_to_user_ids = self.context.get('pending_to_user_ids', set())
		return 'pending' if obj.user_id in pending_to_user_ids else 'none'

	@extend_schema_field(serializers.IntegerField(allow_null=True))
	def get_buddy_request_id(self, obj):
		pending_request_id_by_to_user_id = self.context.get('pending_request_id_by_to_user_id', {})
		return pending_request_id_by_to_user_id.get(obj.user_id)
	
class BuddyConnectSerializer(serializers.Serializer):
	to_user = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())
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
	"""Request body for updating profile experience and interests."""
	experience = serializers.CharField(required=False, allow_blank=True)
	interests = serializers.ListField(child=serializers.CharField(), required=False)


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


class GoogleAuthResponseSerializer(serializers.Serializer):
	user = UserSerializer(read_only=True)
	token = serializers.CharField()

class LogoutResponseSerializer(serializers.Serializer):
    detail = serializers.CharField()
