from rest_framework import serializers

from accounts.models import User
from .models import (
	Profile,
	Goal,
	Partnership,
	Match,
	Task,
	SubTask,
	TimerSession,
	Evidence,
	Notification,
    Conversation,
    Message,
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


class ProfileSerializer(serializers.ModelSerializer):
	user = UserSerializer(read_only=True)

	class Meta:
		model = Profile
		fields = [
			'id',
			'user',
			'bio',
			'location',
			'time_zone',
			'focus_areas',
			'availability',
			'communication_styles',
			'created_at',
			'updated_at',
		]


class GoalSerializer(serializers.ModelSerializer):
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

	def get_last_message(self, obj):
		message = obj.messages.order_by('-created_at').first()
		return MessageSerializer(message).data if message else None


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

