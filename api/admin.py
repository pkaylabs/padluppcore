from django.contrib import admin

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


@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
	list_display = ('id', 'user', 'location', 'time_zone', 'created_at')
	search_fields = ('user__email', 'user__name', 'location')


@admin.register(Goal)
class GoalAdmin(admin.ModelAdmin):
	list_display = ('id', 'user', 'title', 'is_active', 'start_date', 'target_date')
	search_fields = ('title', 'user__email', 'user__name')
	list_filter = ('is_active',)


@admin.register(Partnership)
class PartnershipAdmin(admin.ModelAdmin):
	list_display = ('id', 'user_a', 'user_b', 'is_active', 'paused', 'created_at')
	search_fields = ('user_a__email', 'user_b__email')
	list_filter = ('is_active', 'paused')


@admin.register(Match)
class MatchAdmin(admin.ModelAdmin):
	list_display = ('id', 'from_user', 'to_user', 'action', 'created_at')
	search_fields = ('from_user__email', 'to_user__email')
	list_filter = ('action',)


@admin.register(Task)
class TaskAdmin(admin.ModelAdmin):
	list_display = ('id', 'title', 'owner', 'status', 'due_at', 'is_shared', 'is_overdue')
	search_fields = ('title', 'owner__email', 'owner__name')
	list_filter = ('status', 'is_shared', 'is_overdue')


@admin.register(SubTask)
class SubTaskAdmin(admin.ModelAdmin):
	list_display = ('id', 'title', 'task', 'owner', 'status')
	search_fields = ('title', 'task__title', 'owner__email')
	list_filter = ('status',)


@admin.register(TimerSession)
class TimerSessionAdmin(admin.ModelAdmin):
	list_display = ('id', 'user', 'task', 'subtask', 'started_at', 'ended_at')
	search_fields = ('user__email', 'task__title', 'subtask__title')


@admin.register(Evidence)
class EvidenceAdmin(admin.ModelAdmin):
	list_display = ('id', 'task', 'subtask', 'submitted_by', 'approved', 'submitted_at', 'reviewed_at')
	search_fields = ('task__title', 'subtask__title', 'submitted_by__email')
	list_filter = ('approved',)


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
	list_display = ('id', 'user', 'type', 'is_read', 'created_at')
	search_fields = ('user__email', 'type')
	list_filter = ('is_read',)


@admin.register(Conversation)
class ConversationAdmin(admin.ModelAdmin):
	list_display = ('id', 'partnership', 'created_at')
	search_fields = ('partnership__user_a__email', 'partnership__user_b__email')


@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
	list_display = ('id', 'conversation', 'sender', 'text', 'is_read', 'created_at')
	search_fields = ('sender__email', 'text')
	list_filter = ('is_read',)

