"""One policy boundary for community REST, legacy REST and websocket callers."""
from datetime import timedelta

from django.db.models import Q
from django.utils import timezone

from .community_models import CommunityCreatorApproval, CommunityMembership, CommunityTaskMembership


def active_user(user):
    return bool(user and user.is_authenticated and user.is_active and not getattr(user, 'deleted', False))


def is_internal(user):
    return active_user(user) and any(getattr(user, flag, False) for flag in ('is_superuser', 'is_staff', 'is_founder'))


def can_create_group(user):
    return active_user(user) and (is_internal(user) or CommunityCreatorApproval.objects.filter(user=user, approved=True).exists())


def group_membership(group, user):
    if not active_user(user):
        return None
    return CommunityMembership.objects.filter(group=group, user=user).first()


def can_read_group(group, user):
    if not active_user(user):
        return False
    if is_internal(user):
        return True
    membership = group_membership(group, user)
    return bool(membership and membership.state in ('active', 'left'))


def can_manage_group(group, user):
    membership = group_membership(group, user)
    return is_internal(user) or bool(membership and membership.state == 'active' and membership.role == 'admin')


def can_moderate_group(group, user):
    membership = group_membership(group, user)
    return is_internal(user) or bool(membership and membership.state == 'active' and membership.role in ('admin', 'moderator'))


def group_admin_count(group):
    return group.memberships.filter(state='active', role='admin', user__is_active=True, user__deleted=False).count()


def can_post_group(group, user, post_type='text'):
    if not active_user(user) or group.status != 'active':
        return False
    membership = group_membership(group, user)
    if not is_internal(user) and not (membership and membership.state == 'active'):
        return False
    if membership and membership.muted_until and membership.muted_until > timezone.now():
        return False
    return bool(group.post_permissions.get(post_type, False))


def task_membership(task, user):
    if not active_user(user):
        return None
    return CommunityTaskMembership.objects.filter(task=task, user=user).first()


def can_manage_task(task, user):
    membership = task_membership(task, user)
    return is_internal(user) or bool(membership and membership.state == 'active' and membership.role == 'admin')


def can_access_goal(goal, user):
    if not active_user(user):
        return False
    task = getattr(goal, 'community_task', None)
    if task:
        membership = task_membership(task, user)
        return is_internal(user) or bool(membership and membership.state in ('active', 'left'))
    return bool(goal.user_id == user.id or goal.members.filter(id=user.id).exists()
                or (goal.partnership_id and user.id in (goal.partnership.user_a_id, goal.partnership.user_b_id)))


def can_write_goal(goal, user):
    if not can_access_goal(goal, user):
        return False
    task = getattr(goal, 'community_task', None)
    if task:
        membership = task_membership(task, user)
        return task.status == 'active' and bool(is_internal(user) or (membership and membership.state == 'active'))
    return goal.is_active


def can_read_conversation(conversation, user):
    if not active_user(user):
        return False
    group = getattr(conversation, 'community_group', None)
    if group:
        return can_read_group(group, user)
    if conversation.goal_id:
        return can_access_goal(conversation.goal, user)
    if conversation.partnership_id:
        return user.id in (conversation.partnership.user_a_id, conversation.partnership.user_b_id)
    return conversation.members.filter(id=user.id).exists()


def can_write_conversation(conversation, user, post_type='text'):
    if not can_read_conversation(conversation, user):
        return False
    group = getattr(conversation, 'community_group', None)
    if group:
        return can_post_group(group, user, post_type)
    if conversation.goal_id:
        return can_write_goal(conversation.goal, user)
    return True


def _period_filter(membership, resources, group=False):
    periods = list(membership.periods.order_by('joined_at', 'id'))
    predicate = Q(pk__in=[])
    for index, period in enumerate(periods):
        # Only the first admission includes the pre-join history allowance.
        # Later admissions must not disclose content sent during an absence.
        segment = Q(pk__isnull=False)
        if index or not resources:
            start = period.joined_at - timedelta(days=30) if group and not index else period.joined_at
            segment &= Q(created_at__gte=start)
        if period.ended_at:
            segment &= Q(created_at__lte=period.ended_at)
        predicate |= segment
    return predicate


def visible_messages(queryset, user, resources=False):
    if not active_user(user):
        return queryset.none()
    from .models import Conversation
    predicate = Q(pk__in=[])
    conversations = Conversation.objects.filter(id__in=queryset.values('conversation_id')).select_related(
        'community_group', 'goal', 'goal__community_task', 'partnership')
    for conversation in conversations:
        if not can_read_conversation(conversation, user):
            continue
        segment = Q(conversation_id=conversation.id)
        group = getattr(conversation, 'community_group', None)
        task = getattr(conversation.goal, 'community_task', None) if conversation.goal_id else None
        if not is_internal(user):
            if group:
                segment &= _period_filter(group_membership(group, user), resources, group=True)
            elif task:
                segment &= _period_filter(task_membership(task, user), resources)
        predicate |= segment
    return queryset.filter(predicate).exclude(hidden_for__user=user)
