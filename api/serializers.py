
from rest_framework import serializers
from drf_spectacular.utils import extend_schema_field

import json


from accounts.models import User
from .models import (
	Profile,
	Goal,
	Partnership,
	Event,
	BuddyRequest,
	Match,
	Task,
	SubTask,
	TimerSession,
	Evidence,
	Notification,
	Conversation,
	Message,
	Waitlister,
)


class UserSerializer(serializers.ModelSerializer):
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
		]


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
	user = UserSerializer(read_only=True)
	interests = CommaSeparatedListField(required=False)

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
		]


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


class GoalSerializer(serializers.ModelSerializer):
	user = UserSerializer(read_only=True)
	class Meta:
		model = Goal
		fields = [
			'id',
			'user',
			'title',
			'description',
			'start_date',
			'target_date',
			'is_active',
			'status',
			'created_at',
			'updated_at',
		]
		read_only_fields = ['user']


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


class TaskSerializer(serializers.ModelSerializer):
	class Meta:
		model = Task
		fields = [
			'id',
			'goal',
			'partnership',
			'owner',
			'title',
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
			'status',
			'created_at',
			'updated_at',
		]


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
		read_only_fields = ['submitted_by', 'submitted_at', 'reviewed_at']


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


class MessageSerializer(serializers.ModelSerializer):
	sender = UserSerializer(read_only=True)

	class Meta:
		model = Message
		fields = [
			'id',
			'conversation',
			'sender',
			'text',
			'is_read',
			'created_at',
			'updated_at',
		]
		read_only_fields = ['sender', 'is_read']


class ConversationSerializer(serializers.ModelSerializer):
	last_message = serializers.SerializerMethodField()

	class Meta:
		model = Conversation
		fields = [
			'id',
			'partnership',
			'last_message',
			'created_at',
			'updated_at',
		]

	@extend_schema_field(MessageSerializer)
	def get_last_message(self, obj):
		message = obj.messages.order_by('-created_at').first()
		return MessageSerializer(message).data if message else None


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
	creator = UserSerializer(read_only=True)
	participants = UserSerializer(read_only=True, many=True)
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
	from_user = UserSerializer(read_only=True)
	to_user = UserSerializer(read_only=True)

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
	user = UserSerializer(read_only=True)
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
	avatar = serializers.CharField()


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
