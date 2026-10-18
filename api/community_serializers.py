import json

from django.contrib.auth import get_user_model
from django.db.models import Q
from django.utils import timezone
from rest_framework import serializers

from .community_access import (
    can_access_goal, can_manage_group, can_manage_task, can_moderate_group, can_post_group,
    group_admin_count, group_membership, is_internal, task_membership,
)
from .community_models import CommunityCategory, CommunityGroup, CommunityTask, standard_post_permissions
from .community_services import enrollment_status


def user_data(user, request=None):
    if not user:
        return None
    from .awards import AWARD_BY_KEY
    avatar = None
    if user and user.avatar:
        try:
            avatar = user.avatar.url
            if request:
                avatar = request.build_absolute_uri(avatar)
        except (ValueError, AttributeError):
            pass
    achievements = [
        {'id': award.id, 'key': award.award_key, 'name': AWARD_BY_KEY[award.award_key].title}
        for award in user.awards.all() if award.award_key in AWARD_BY_KEY
    ]
    return {'id': user.id, 'name': user.name, 'avatar': avatar, 'achievements': achievements}


class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = CommunityCategory
        fields = ['id', 'name']


class GroupWriteSerializer(serializers.ModelSerializer):
    class Meta:
        model = CommunityGroup
        fields = ['name', 'description', 'category', 'visibility', 'image', 'rules', 'post_permissions']
        extra_kwargs = {'category': {'required': True}, 'name': {'allow_blank': False}, 'image': {'required': False, 'allow_null': True}}

    def validate_image(self, image):
        if image and image.size > 5 * 1024 * 1024:
            raise serializers.ValidationError('Group images must be 5 MB or smaller.')
        return image

    def validate_rules(self, rules):
        if not isinstance(rules, list) or len(rules) > 50 or any(not isinstance(rule, str) or not rule.strip() or len(rule) > 2000 for rule in rules):
            raise serializers.ValidationError('Use a list of up to 50 non-empty rules, each at most 2000 characters.')
        return [rule.strip() for rule in rules]

    def validate_post_permissions(self, permissions):
        supported = standard_post_permissions()
        if not isinstance(permissions, dict) or set(permissions) - set(supported) or any(type(value) is not bool for value in permissions.values()):
            raise serializers.ValidationError('Use boolean values for the supported post types.')
        return {**supported, **permissions}


class GroupSerializer(serializers.ModelSerializer):
    category = CategorySerializer()
    creator = serializers.SerializerMethodField()
    conversation_id = serializers.SerializerMethodField()
    membership = serializers.SerializerMethodField()
    member_count = serializers.SerializerMethodField()
    admin_count = serializers.SerializerMethodField()
    joins_paused = serializers.SerializerMethodField()
    can_manage = serializers.SerializerMethodField()
    can_moderate = serializers.SerializerMethodField()
    can_post = serializers.SerializerMethodField()
    report_count = serializers.SerializerMethodField()
    last_activity_at = serializers.DateTimeField(read_only=True, allow_null=True, default=None)

    class Meta:
        model = CommunityGroup
        fields = ['id', 'name', 'description', 'category', 'image', 'visibility', 'status', 'conversation_id',
                  'member_count', 'admin_count', 'membership', 'can_manage', 'can_moderate', 'can_post',
                  'joins_paused', 'rules', 'post_permissions', 'creator', 'created_at', 'report_count', 'last_activity_at']

    @property
    def user(self):
        return self.context['request'].user

    def get_creator(self, obj):
        return user_data(obj.creator, self.context.get('request'))

    def get_conversation_id(self, obj):
        member = group_membership(obj, self.user)
        return obj.conversation_id if is_internal(self.user) or (member and member.state in ('active', 'left')) else None

    def get_membership(self, obj):
        member = group_membership(obj, self.user)
        return {'role': member.role, 'state': member.state, 'notifications_muted': member.notifications_muted} if member else None

    def get_member_count(self, obj):
        return obj.memberships.filter(state='active', user__is_active=True, user__deleted=False).count()

    def get_admin_count(self, obj):
        return group_admin_count(obj)

    def get_joins_paused(self, obj):
        return obj.status != 'active' or group_admin_count(obj) < 2

    def get_can_manage(self, obj):
        return can_manage_group(obj, self.user)

    def get_can_moderate(self, obj):
        return can_moderate_group(obj, self.user)

    def get_can_post(self, obj):
        return any(can_post_group(obj, self.user, post_type) for post_type in standard_post_permissions())

    def get_report_count(self, obj):
        return getattr(obj, 'open_report_count', 0) if can_moderate_group(obj, self.user) else 0


class MemberActionSerializer(serializers.Serializer):
    user_id = serializers.PrimaryKeyRelatedField(source='user', queryset=get_user_model().objects.all())
    action = serializers.ChoiceField(choices=['invite', 'role', 'remove', 'ban', 'unban', 'mute'])
    role = serializers.ChoiceField(choices=['admin', 'moderator', 'member'], default='member')
    reason = serializers.CharField(required=False, allow_blank=True, default='', max_length=4000)
    until = serializers.DateTimeField(required=False, allow_null=True)


class DecisionSerializer(serializers.Serializer):
    user_id = serializers.PrimaryKeyRelatedField(source='user', queryset=get_user_model().objects.filter(is_active=True, deleted=False))
    decision = serializers.ChoiceField(choices=['approve', 'reject'])


class LeaveSerializer(serializers.Serializer):
    reason = serializers.CharField(max_length=4000, allow_blank=False)
    feedback = serializers.CharField(max_length=10000, required=False, allow_blank=True, default='')
    transfer_to = serializers.IntegerField(min_value=1, required=False, allow_null=True)


class LifecycleSerializer(serializers.Serializer):
    status = serializers.CharField(max_length=20)
    reason = serializers.CharField(max_length=4000, allow_blank=True, default='')


class ReportSerializer(serializers.Serializer):
    reason = serializers.CharField(max_length=255)
    details = serializers.CharField(max_length=10000, required=False, allow_blank=True, default='')
    user_id = serializers.PrimaryKeyRelatedField(source='reported_user', queryset=get_user_model().objects.filter(deleted=False), required=False)


class MilestoneSerializer(serializers.Serializer):
    title = serializers.CharField(max_length=255)
    due_at = serializers.DateTimeField(required=False, allow_null=True)


class TaskWriteSerializer(serializers.Serializer):
    group = serializers.PrimaryKeyRelatedField(queryset=CommunityGroup.objects.all())
    title = serializers.CharField(max_length=255)
    description = serializers.CharField(max_length=20000, allow_blank=True, default='')
    category = serializers.CharField(max_length=100)
    start_date = serializers.DateField()
    target_date = serializers.DateField()
    invitation_deadline = serializers.DateTimeField()
    member_limit = serializers.IntegerField(min_value=1, max_value=10000, default=8)
    visibility = serializers.ChoiceField(choices=['public', 'private'], default='public')
    approval_required = serializers.BooleanField(default=False)
    checkin_frequency = serializers.ChoiceField(choices=['DAILY', '3-DAYS', 'WEEKLY', 'BI-WEEKLY', 'CUSTOM'])
    custom_interval_days = serializers.IntegerField(min_value=1, max_value=365, required=False, allow_null=True)
    milestones = MilestoneSerializer(many=True, required=False, default=list, max_length=100)
    invited_user_ids = serializers.ListField(child=serializers.IntegerField(min_value=1), required=False, default=list, max_length=100)
    idempotency_key = serializers.CharField(max_length=100)
    cover = serializers.FileField(required=False, allow_null=True)
    limits_approval_reason = serializers.CharField(max_length=4000, required=False, allow_blank=True, default='')

    def to_internal_value(self, data):
        if hasattr(data, 'getlist'):
            values = dict(data.items())
            for field in ('milestones', 'invited_user_ids'):
                if field in values and isinstance(values[field], str):
                    try:
                        values[field] = json.loads(values[field])
                    except (TypeError, ValueError):
                        raise serializers.ValidationError({field: 'Supply a valid JSON array.'})
            data = values
        return super().to_internal_value(data)

    def validate(self, attrs):
        # Retry payloads are still parsed but may use an already elapsed deadline.
        retry = CommunityTask.objects.filter(creator=self.context['request'].user, idempotency_key=attrs['idempotency_key']).exists()
        if attrs['target_date'] < attrs['start_date']:
            raise serializers.ValidationError({'target_date': 'The deadline must follow the start date.'})
        extended = attrs['member_limit'] > 8 or (attrs['target_date'] - attrs['start_date']).days > 14
        if extended and not is_internal(self.context['request'].user):
            raise serializers.ValidationError('More than eight members or fourteen days requires internal-admin approval.')
        if extended and not attrs['limits_approval_reason'].strip():
            raise serializers.ValidationError({'limits_approval_reason': 'Record a reason for the internal-admin exception.'})
        if not retry and attrs['invitation_deadline'] <= timezone.now():
            raise serializers.ValidationError({'invitation_deadline': 'The invitation deadline must be in the future.'})
        if attrs['invitation_deadline'].date() > attrs['target_date']:
            raise serializers.ValidationError({'invitation_deadline': 'Invitations must close by the task deadline.'})
        if attrs['checkin_frequency'] == 'CUSTOM' and not attrs.get('custom_interval_days'):
            raise serializers.ValidationError({'custom_interval_days': 'Specify a custom interval.'})
        for milestone in attrs['milestones']:
            due = milestone.get('due_at')
            if due and not attrs['start_date'] <= due.date() <= attrs['target_date']:
                raise serializers.ValidationError({'milestones': 'Milestone deadlines must be within the task dates.'})
        if attrs.get('cover'):
            cover = attrs['cover']
            if cover.size > 15 * 1024 * 1024 or not getattr(cover, 'content_type', '').startswith(('image/', 'video/')):
                raise serializers.ValidationError({'cover': 'Use image/video cover media of 15 MB or smaller.'})
        invited_ids = set(attrs['invited_user_ids'])
        if invited_ids and get_user_model().objects.filter(id__in=invited_ids, is_active=True, deleted=False).count() != len(invited_ids):
            raise serializers.ValidationError({'invited_user_ids': 'One or more users are unavailable.'})
        return attrs


class CommunityTaskSerializer(serializers.ModelSerializer):
    title = serializers.CharField(source='goal.title')
    description = serializers.CharField(source='goal.description')
    category = serializers.CharField(source='goal.category')
    start_date = serializers.DateField(source='goal.start_date')
    target_date = serializers.DateField(source='goal.target_date')
    checkin_frequency = serializers.CharField(source='goal.checkin_frequency')
    pod_id = serializers.IntegerField(source='goal_id')
    conversation_id = serializers.SerializerMethodField()
    member_count = serializers.SerializerMethodField()
    enrollment_status = serializers.SerializerMethodField()
    can_manage = serializers.SerializerMethodField()
    can_join = serializers.SerializerMethodField()
    progress = serializers.SerializerMethodField()
    members = serializers.SerializerMethodField()
    milestones = serializers.SerializerMethodField()
    membership = serializers.SerializerMethodField()
    invitation_status = serializers.SerializerMethodField()
    milestone_completion = serializers.SerializerMethodField()
    checkin_participation = serializers.SerializerMethodField()
    cover = serializers.SerializerMethodField()

    class Meta:
        model = CommunityTask
        fields = ['id', 'group', 'goal_id', 'pod_id', 'conversation_id', 'title', 'description', 'category',
                  'start_date', 'target_date', 'invitation_deadline', 'member_limit', 'member_count', 'visibility',
                  'status', 'enrollment_status', 'can_manage', 'can_join', 'progress', 'cover', 'checkin_frequency',
                  'custom_interval_days', 'members', 'milestones', 'membership', 'invitation_status',
                  'approval_required', 'milestone_completion', 'checkin_participation']

    @property
    def user(self):
        return self.context['request'].user

    def get_conversation_id(self, obj):
        member = task_membership(obj, self.user)
        return obj.goal.conversation.id if is_internal(self.user) or (member and member.state in ('active', 'left')) else None

    def get_member_count(self, obj):
        # Disabled accounts retain their reserved slot until an admin removes
        # their membership; use the same count as transactional enrollment.
        return obj.memberships.filter(state='active').count()

    def get_enrollment_status(self, obj):
        return enrollment_status(obj)

    def get_can_manage(self, obj):
        return can_manage_task(obj, self.user)

    def get_can_join(self, obj):
        member = task_membership(obj, self.user)
        source = group_membership(obj.group, self.user)
        allowed = is_internal(self.user) or bool(source and source.state == 'active') or obj.invitations.filter(user=self.user, status='pending').exists()
        return allowed and enrollment_status(obj) == 'open' and not (member and member.state in ('active', 'pending', 'removed', 'banned'))

    def get_progress(self, obj):
        if not can_access_goal(obj.goal, self.user):
            return 0
        members = obj.memberships.filter(state='active', user__is_active=True, user__deleted=False)
        values = []
        own = task_membership(obj, self.user)
        for member in members:
            checkins = obj.goal.checkins.filter(user_id=member.user_id, submitted_at__isnull=False)
            if own and own.state == 'left' and not is_internal(self.user):
                checkins = checkins.filter(submitted_at__lte=own.left_at)
            latest = checkins.order_by('-submitted_at', '-id').first()
            values.append(latest.completion_percent if latest else 0)
        return round(sum(values) / len(values), 1) if values else 0

    def get_members(self, obj):
        if not can_access_goal(obj.goal, self.user):
            return []
        members = obj.memberships.filter(state='active', user__is_active=True, user__deleted=False)
        own = task_membership(obj, self.user)
        if own and own.state == 'left' and not is_internal(self.user):
            members = members.filter(joined_at__lte=own.left_at)
        return [{'id': m.id, 'user': user_data(m.user, self.context.get('request')), 'role': m.role, 'state': m.state, 'joined_at': m.joined_at}
                for m in members.select_related('user').prefetch_related('user__awards')]

    def get_milestones(self, obj):
        milestones = list(obj.goal.tasks.values('id', 'title', 'due_at', 'completed', 'status'))
        if not can_access_goal(obj.goal, self.user):
            for milestone in milestones:
                milestone['completed'], milestone['status'] = False, 'planned'
        return milestones

    def get_membership(self, obj):
        member = task_membership(obj, self.user)
        return {'role': member.role, 'state': member.state} if member else None

    def get_invitation_status(self, obj):
        return obj.invitations.filter(user=self.user).values_list('status', flat=True).first()

    def get_cover(self, obj):
        if not obj.cover:
            return None
        path = f'/api-v1/community/tasks/{obj.id}/cover/'
        return self.context['request'].build_absolute_uri(path)

    def get_milestone_completion(self, obj):
        return {'completed': obj.goal.tasks.filter(completed=True).count() if can_access_goal(obj.goal, self.user) else 0, 'total': obj.goal.tasks.count()}

    def get_checkin_participation(self, obj):
        if not can_access_goal(obj.goal, self.user):
            return {'submitted': 0, 'total': 0}
        checkins = obj.goal.checkins.filter(user_id__in=obj.memberships.filter(state='active').values('user_id'), scheduled_for__lte=timezone.localdate())
        own = task_membership(obj, self.user)
        if own and own.state == 'left' and not is_internal(self.user):
            checkins = checkins.filter(created_at__lte=own.left_at).filter(Q(submitted_at__isnull=True) | Q(submitted_at__lte=own.left_at))
        return {'submitted': checkins.filter(submitted_at__isnull=False).count(), 'total': checkins.count()}


class TaskPatchSerializer(serializers.Serializer):
    title = serializers.CharField(max_length=255, required=False)
    description = serializers.CharField(max_length=20000, allow_blank=True, required=False)
    visibility = serializers.ChoiceField(choices=['public', 'private'], required=False)
    checkin_frequency = serializers.ChoiceField(choices=['DAILY', '3-DAYS', 'WEEKLY', 'BI-WEEKLY', 'CUSTOM'], required=False)
    custom_interval_days = serializers.IntegerField(min_value=1, max_value=365, required=False, allow_null=True)

    def validate(self, attrs):
        task = self.context['task']
        frequency = attrs.get('checkin_frequency', task.goal.checkin_frequency)
        if frequency == 'CUSTOM' and not attrs.get('custom_interval_days', task.custom_interval_days):
            raise serializers.ValidationError({'custom_interval_days': 'Specify a custom interval.'})
        return attrs
