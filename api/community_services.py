"""Transactional community operations shared with existing goal/chat endpoints."""
from datetime import datetime, time, timedelta, timezone as datetime_timezone

from django.conf import settings
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from rest_framework.exceptions import PermissionDenied, ValidationError

from .community_access import (
    active_user, can_create_group, can_manage_group, can_manage_task, can_post_group,
    group_admin_count, group_membership, is_internal, task_membership,
)
from .community_models import (
    CommunityAudit, CommunityGroup, CommunityInactivityReview, CommunityInvite,
    CommunityMembership, CommunityMembershipPeriod, CommunityTask,
    CommunityTaskInvitation, CommunityTaskMembership, CommunityTaskPeriod,
)
from .models import (
    CheckinReminderLog, Conversation, ConversationMembership, Goal, GoalCheckin,
    GoalMembership, Message, Notification, Task,
)


COMMUNITY_CHECKIN_REMINDER_HOUR_UTC = 20


def audit(actor, action, target=None, reason='', group=None, metadata=None):
    if group is None:
        if isinstance(target, CommunityGroup):
            group = target
        elif isinstance(target, CommunityTask):
            group = target.group
    return CommunityAudit.objects.create(
        actor=actor, action=action, group=group,
        task=target if isinstance(target, CommunityTask) else None,
        target_type=target.__class__.__name__ if target else '',
        target_id=str(target.pk) if target else '', reason=reason or '', outcome=metadata or {},
    )


def notify(user_ids, event, payload, reminder=False):
    from django.contrib.auth import get_user_model
    users = get_user_model().objects.filter(id__in=set(user_ids), is_active=True, deleted=False)
    if reminder:
        users = users.filter(notify_on_reminders=True)
    labels = {
        'community_invitation': 'You have been invited to a community group.',
        'community_join_requested': 'A member has requested to join your group.',
        'community_joined': 'Your community group membership is now active.',
        'community_join_decision': 'Your community join request has been reviewed.',
        'community_membership_changed': 'Your community membership or role has changed.',
        'community_group_updated': 'Your community details or rules have changed.',
        'community_status_changed': 'Your community status has changed.',
        'community_task_created': 'A new task is available in your community.',
        'community_task_invitation': 'You have been invited to a task and its pod.',
        'community_task_join_requested': 'A member has requested to join your pod.',
        'community_task_join_decision': 'Your task join request has been reviewed.',
        'community_pod_joined': 'Your pod membership is now active.',
        'community_pod_membership_changed': 'Your pod membership has changed.',
        'community_task_status_changed': 'Your task and pod status have changed.',
        'community_task_settings_changed': 'Your pod settings have changed.',
        'community_task_full': 'Your task has reached its member limit.',
        'community_invitation_closed': 'The task invitation deadline has passed.',
        'community_creation_permission': 'Your group creation permission has changed.',
    }
    payload = {'message': labels.get(event, 'There is an update for you on Padlupp.'), **payload}
    # Delivery hooks run after commit; records roll back with their operation.
    for user in users:
        Notification.objects.create(user=user, type=event, payload=payload)


def require_reason(reason):
    if not isinstance(reason, str):
        raise ValidationError({'reason': 'A written reason is required.'})
    reason = reason.strip()
    if not reason:
        raise ValidationError({'reason': 'A reason is required.'})
    return reason


def _activate_group(group, user, role='member'):
    membership, _ = CommunityMembership.objects.get_or_create(group=group, user=user)
    if membership.state != 'active':
        membership.joined_at = timezone.now()
        membership.left_at = None
        membership.state = 'active'
        CommunityMembershipPeriod.objects.create(membership=membership, joined_at=membership.joined_at)
    membership.role = role
    membership.save()
    ConversationMembership.objects.get_or_create(conversation=group.conversation, user=user, defaults={'added_by': group.creator})
    return membership


def _end_group_membership(membership, state, reason, feedback=''):
    now = timezone.now()
    membership.state, membership.left_at = state, now
    membership.reason, membership.feedback = reason, feedback
    if state == 'banned':
        membership.misconduct = True
    membership.save()
    membership.periods.filter(ended_at__isnull=True).update(ended_at=now)
    # Leavers are no longer notification/socket recipients. Their read access is
    # derived from the historical membership, not this legacy join table.
    ConversationMembership.objects.filter(conversation=membership.group.conversation, user=membership.user).delete()


def notify_admin_shortage(group, previous_count):
    current = group_admin_count(group)
    if previous_count >= 2 and current < 2:
        notify(group.memberships.filter(state='active', role='admin').values_list('user_id', flat=True),
               'community_admin_required', {'group_id': group.id, 'message': 'New member joins are paused. Choose and enroll another admin.'})


@transaction.atomic
def create_group(actor, data):
    if not can_create_group(actor):
        raise PermissionDenied('Only internal admins and explicitly approved creators may create groups.')
    conversation = Conversation.objects.create(name=data['name'], is_group=True)
    group = CommunityGroup.objects.create(creator=actor, conversation=conversation, **data)
    _activate_group(group, actor, 'admin')
    Message.objects.create(conversation=conversation, sender=actor, text=f"Welcome to {group.name}! Review the group rules before getting started.")
    audit(actor, 'group.created', group)
    return group


@transaction.atomic
def join_group(group, actor, token=None):
    group = CommunityGroup.objects.select_for_update().get(pk=group.pk)
    if not active_user(actor) or group.status != 'active':
        raise PermissionDenied('This group is not accepting members.')
    membership = group_membership(group, actor)
    if membership and membership.state in ('banned', 'removed'):
        raise PermissionDenied('An admin must restore your access before you can rejoin.')
    if membership and membership.state == 'active':
        return membership
    invites = group.invitations.select_for_update().filter(status='pending', expires_at__gt=timezone.now())
    invitation = invites.filter(user=actor).order_by('-created_at').first()
    if token:
        try:
            linked = invites.filter(token=token).filter(Q(user__isnull=True) | Q(user=actor)).first()
        except (ValueError, TypeError, DjangoValidationError):
            linked = None
        if not linked:
            raise ValidationError({'token': 'This invitation is invalid or expired.'})
        invitation = invitation or linked
    invited_admin = invitation and invitation.user_id == actor.id and invitation.role == 'admin'
    if group_admin_count(group) < 2 and not invited_admin:
        raise ValidationError({'detail': 'New member joins are paused until a second admin is appointed.'})
    # A generic private link identifies the group; it does not bypass approval.
    if group.visibility == 'private' and not (invitation and invitation.user_id == actor.id):
        membership, _ = CommunityMembership.objects.get_or_create(group=group, user=actor)
        membership.state = 'pending'
        membership.save()
        notify(group.memberships.filter(state='active', role='admin').values_list('user_id', flat=True),
               'community_join_requested', {'group_id': group.id, 'user_id': actor.id})
        return membership
    membership = _activate_group(group, actor, 'admin' if invited_admin else 'member')
    if invitation and invitation.user_id:
        invitation.status = 'accepted'
        invitation.save(update_fields=['status', 'updated_at'])
    audit(actor, 'group.joined', membership, group=group)
    notify([actor.id], 'community_joined', {'group_id': group.id})
    return membership


@transaction.atomic
def leave_group(group, actor, reason, feedback=''):
    group = CommunityGroup.objects.select_for_update().get(pk=group.pk)
    membership = group_membership(group, actor)
    if not membership or membership.state != 'active':
        raise PermissionDenied('You are not an active member.')
    reason = require_reason(reason)
    before = group_admin_count(group)
    if membership.role == 'admin' and before == 1 and group.memberships.filter(state='active').exclude(user=actor).exists():
        raise ValidationError('Appoint another admin before leaving.')
    _end_group_membership(membership, 'left', reason, feedback)
    notify_admin_shortage(group, before)
    audit(actor, 'group.left', membership, reason, group=group)
    return membership


@transaction.atomic
def manage_group_member(group, actor, user, action, role='member', reason='', until=None):
    group = CommunityGroup.objects.select_for_update().get(pk=group.pk)
    if not can_manage_group(group, actor):
        raise PermissionDenied('Only group admins can manage membership.')
    if role not in ('admin', 'moderator', 'member'):
        raise ValidationError({'role': 'Choose admin, moderator or member.'})
    before = group_admin_count(group)
    membership = CommunityMembership.objects.filter(group=group, user=user).first()
    if action == 'invite':
        if group.status != 'active' or not active_user(user):
            raise ValidationError('This group or user cannot accept invitations.')
        if membership and membership.state in ('banned', 'removed'):
            raise ValidationError('Restore the membership before inviting this user.')
        invitation = CommunityInvite.objects.create(group=group, user=user, invited_by=actor, role=role,
                                                     expires_at=timezone.now() + timedelta(days=7))
        notify([user.id], 'community_invitation', {'group_id': group.id, 'invitation_id': invitation.id, 'role': role})
        audit(actor, 'group.invited', invitation, group=group)
        return invitation
    if not membership:
        raise ValidationError('Membership not found.')
    if action == 'role':
        if membership.state != 'active' or not active_user(user):
            raise ValidationError('Only active members can be promoted.')
        if membership.role == 'admin' and role != 'admin' and before <= 1:
            raise ValidationError('The group must retain an admin.')
        membership.role = role
        membership.save(update_fields=['role', 'updated_at'])
    elif action in ('remove', 'ban'):
        reason = require_reason(reason)
        if membership.role == 'admin' and membership.state == 'active' and active_user(user) and before <= 1:
            raise ValidationError('Appoint a replacement admin first.')
        _end_group_membership(membership, 'removed' if action == 'remove' else 'banned', reason)
    elif action == 'unban':
        if membership.state not in ('banned', 'removed'):
            raise ValidationError('Membership is not removed or banned.')
        membership.state = 'left' if membership.periods.exists() else 'rejected'
        membership.save(update_fields=['state', 'updated_at'])
    elif action == 'mute':
        reason = require_reason(reason)
        if until is not None and until <= timezone.now():
            raise ValidationError({'until': 'Mute end must be in the future.'})
        membership.muted_until = until
        membership.save(update_fields=['muted_until', 'updated_at'])
    else:
        raise ValidationError({'action': 'Unsupported membership action.'})
    notify_admin_shortage(group, before)
    notify([user.id], 'community_membership_changed', {'group_id': group.id, 'action': action, 'role': membership.role, 'reason': reason})
    audit(actor, 'group.member.' + action, membership, reason, group=group)
    return membership


@transaction.atomic
def decide_group_request(group, actor, user, decision):
    group = CommunityGroup.objects.select_for_update().get(pk=group.pk)
    if not can_manage_group(group, actor):
        raise PermissionDenied()
    membership = group_membership(group, user)
    if not membership or membership.state != 'pending':
        raise ValidationError('No pending request.')
    if decision == 'approve':
        if group.status != 'active' or group_admin_count(group) < 2:
            raise ValidationError('New joins are paused.')
        membership = _activate_group(group, user)
    elif decision == 'reject':
        membership.state = 'rejected'
        membership.save(update_fields=['state', 'updated_at'])
    else:
        raise ValidationError({'decision': 'Choose approve or reject.'})
    audit(actor, 'group.request.' + decision, membership, group=group)
    notify([user.id], 'community_join_decision', {'group_id': group.id, 'decision': decision})
    return membership


@transaction.atomic
def set_group_status(group, actor, status, reason=''):
    group = CommunityGroup.objects.select_for_update().get(pk=group.pk)
    if not can_manage_group(group, actor):
        raise PermissionDenied()
    if status not in ('active', 'archived', 'frozen', 'disabled', 'deleted'):
        raise ValidationError({'status': 'Invalid group status.'})
    if status in ('frozen', 'disabled', 'deleted'):
        reason = require_reason(reason)
    group.status = status
    group.save(update_fields=['status', 'updated_at'])
    audit(actor, 'group.' + status, group, reason)
    notify(group.memberships.filter(state='active').values_list('user_id', flat=True),
           'community_status_changed', {'group_id': group.id, 'status': status, 'reason': reason})
    return group


def enrollment_status(task):
    if task.status != 'active':
        return task.status
    if task.enrollment_closed:
        return 'closed'
    if task.invitation_deadline <= timezone.now():
        return 'expired'
    if task.memberships.filter(state='active').count() >= task.member_limit:
        return 'full'
    return 'open'


def _activate_task(task, user, role='member'):
    membership, _ = CommunityTaskMembership.objects.get_or_create(task=task, user=user)
    if membership.state != 'active':
        membership.state, membership.joined_at, membership.left_at = 'active', timezone.now(), None
        CommunityTaskPeriod.objects.create(membership=membership, joined_at=membership.joined_at)
    membership.role = role
    membership.save()
    GoalMembership.objects.update_or_create(goal=task.goal, user=user, defaults={'role': role, 'added_by': task.goal.user})
    ConversationMembership.objects.get_or_create(conversation=task.goal.conversation, user=user, defaults={'added_by': task.goal.user})
    return membership


@transaction.atomic
def create_task(actor, data):
    from django.contrib.auth import get_user_model
    get_user_model().objects.select_for_update().get(pk=actor.pk)
    group = CommunityGroup.objects.select_for_update().get(pk=data['group'].pk)
    if not can_post_group(group, actor, 'task'):
        raise PermissionDenied('Task creation is not permitted in this group.')
    existing = CommunityTask.objects.filter(creator=actor, idempotency_key=data['idempotency_key']).first()
    if existing:
        if existing.group_id != group.id:
            raise ValidationError({'idempotency_key': 'This key has already been used for another group.'})
        return existing, False
    milestones = data.pop('milestones', [])
    invitees = data.pop('invited_user_ids', [])
    goal_fields = {key: data.pop(key) for key in ('title', 'description', 'category', 'start_date', 'target_date', 'checkin_frequency')}
    data.pop('group')
    approved_by = actor if is_internal(actor) and (data['member_limit'] > 8 or (goal_fields['target_date'] - goal_fields['start_date']).days > 14) else None
    goal = Goal.objects.create(user=actor, is_shared=True, is_public=False, status='in_progress', **goal_fields)
    Conversation.objects.get_or_create(goal=goal, defaults={'is_group': True, 'name': goal.title})
    task = CommunityTask.objects.create(group=group, goal=goal, creator=actor, limits_approved_by=approved_by, **data)
    _activate_task(task, actor, 'admin')
    for milestone in milestones:
        Task.objects.create(goal=goal, owner=actor, is_shared=True, title=milestone['title'], due_at=milestone.get('due_at'))
    Message.objects.create(conversation=group.conversation, sender=actor, text=goal.title, kind=Message.KIND_GOAL,
                           metadata={'community_task_id': task.id, 'goal_id': goal.id, 'pod_id': goal.id, 'event': 'community_task_created'})
    audit(actor, 'task.created', task, group=group, metadata={'limits_approved_by': approved_by.id if approved_by else None})
    notify(group.memberships.filter(state='active').exclude(user=actor).values_list('user_id', flat=True),
           'community_task_created', {'group_id': group.id, 'task_id': task.id, 'goal_id': goal.id, 'title': goal.title})
    if invitees:
        invite_task_users(task, actor, invitees)
    generate_task_cycles(task)
    return task, True


@transaction.atomic
def join_task(task, actor, invited=False):
    task = CommunityTask.objects.select_for_update().select_related('goal').get(pk=task.pk)
    membership = task_membership(task, actor)
    if not active_user(actor) or (membership and membership.state in ('removed', 'banned')):
        raise PermissionDenied()
    if membership and membership.state == 'active':
        return membership
    if enrollment_status(task) != 'open':
        raise ValidationError('Enrollment is ' + enrollment_status(task) + '.')
    invitation = task.invitations.select_for_update().filter(user=actor, status='pending').first()
    if invited and not invitation:
        raise ValidationError('No pending invitation.')
    if not invitation:
        source_membership = group_membership(task.group, actor)
        if not is_internal(actor) and not (source_membership and source_membership.state == 'active'):
            raise PermissionDenied('Join through a pod invitation from its owner.')
    if not invited and (task.visibility == 'private' or task.approval_required or (membership and membership.link_approval_required)):
        membership, _ = CommunityTaskMembership.objects.get_or_create(task=task, user=actor)
        membership.state = 'pending'
        membership.save()
        notify(task.memberships.filter(state='active', role='admin').values_list('user_id', flat=True),
               'community_task_join_requested', {'task_id': task.id, 'user_id': actor.id})
        return membership
    membership = _activate_task(task, actor)
    if invitation:
        invitation.status = 'accepted'
        invitation.save(update_fields=['status', 'updated_at'])
    audit(actor, 'task.joined', task, metadata={'user_id': actor.id})
    notify([actor.id], 'community_pod_joined', {'task_id': task.id, 'goal_id': task.goal_id})
    if enrollment_status(task) == 'full':
        notify(task.memberships.filter(state='active', role='admin').values_list('user_id', flat=True),
               'community_task_full', {'task_id': task.id})
    generate_task_cycles(task)
    return membership


@transaction.atomic
def invite_task_users(task, actor, user_ids):
    task = CommunityTask.objects.select_for_update().get(pk=task.pk)
    if not can_manage_task(task, actor):
        raise PermissionDenied()
    if enrollment_status(task) != 'open':
        raise ValidationError('Invitations are not open.')
    from django.contrib.auth import get_user_model
    users = list(get_user_model().objects.filter(id__in=set(user_ids), is_active=True, deleted=False))
    if len(users) != len(set(user_ids)):
        raise ValidationError({'user_ids': 'One or more users are unavailable.'})
    result = []
    for user in users:
        membership = task_membership(task, user)
        if membership and membership.state in ('active', 'removed', 'banned'):
            continue
        invitation, _ = CommunityTaskInvitation.objects.update_or_create(task=task, user=user, defaults={'invited_by': actor, 'status': 'pending'})
        result.append(invitation)
        notify([user.id], 'community_task_invitation', {'task_id': task.id, 'title': task.goal.title, 'invitation_id': invitation.id})
    audit(actor, 'task.invited', task, metadata={'user_ids': [i.user_id for i in result]})
    return result


@transaction.atomic
def request_task_link_join(token, actor):
    from django.core.exceptions import ValidationError as DjangoValidationError
    try:
        task = CommunityTask.objects.select_for_update().get(invite_token=token)
    except (CommunityTask.DoesNotExist, DjangoValidationError, ValueError, TypeError):
        raise ValidationError({'token': 'This pod invitation is invalid.'})
    if not active_user(actor):
        raise PermissionDenied()
    member = task_membership(task, actor)
    if member and member.state in ('removed', 'banned'):
        raise PermissionDenied('Your access to this pod has been removed.')
    if member and member.state == 'active':
        return task, member
    if enrollment_status(task) != 'open':
        raise ValidationError('Enrollment is ' + enrollment_status(task) + '.')
    member, created = CommunityTaskMembership.objects.get_or_create(task=task, user=actor)
    was_pending = not created and member.state == 'pending'
    member.state = 'pending'
    member.link_approval_required = True
    member.save(update_fields=['state', 'link_approval_required', 'updated_at'])
    if not was_pending:
        notify(task.memberships.filter(state='active', role='admin').values_list('user_id', flat=True),
               'community_task_join_requested', {'task_id': task.id, 'user_id': actor.id, 'source': 'pod_link'})
        audit(actor, 'task.link_join_requested', task, metadata={'user_id': actor.id})
    return task, member


@transaction.atomic
def decide_task_request(task, actor, user, decision):
    task = CommunityTask.objects.select_for_update().get(pk=task.pk)
    if not can_manage_task(task, actor):
        raise PermissionDenied()
    membership = task_membership(task, user)
    if not membership or membership.state != 'pending':
        raise ValidationError('No pending request.')
    if decision == 'approve':
        if enrollment_status(task) != 'open':
            raise ValidationError('Enrollment is ' + enrollment_status(task) + '.')
        membership = _activate_task(task, user)
        generate_task_cycles(task)
    elif decision == 'reject':
        membership.state = 'rejected'
        membership.save(update_fields=['state', 'updated_at'])
    else:
        raise ValidationError({'decision': 'Choose approve or reject.'})
    audit(actor, 'task.request.' + decision, task, metadata={'user_id': user.id})
    notify([user.id], 'community_task_join_decision', {'task_id': task.id, 'goal_id': task.goal_id, 'decision': decision})
    return membership


@transaction.atomic
def leave_task(task, actor, reason, transfer_to=None, remove_user=None, feedback=''):
    task = CommunityTask.objects.select_for_update().select_related('goal').get(pk=task.pk)
    if not active_user(actor):
        raise PermissionDenied()
    user = remove_user or actor
    membership = CommunityTaskMembership.objects.filter(task=task, user=user).first()
    if not membership or membership.state != 'active':
        raise ValidationError('No active membership.')
    if remove_user and not can_manage_task(task, actor):
        raise PermissionDenied()
    reason = require_reason(reason)
    if task.goal.user_id == user.id and task.status == 'active':
        replacement = task.memberships.filter(user_id=transfer_to, state='active', user__is_active=True, user__deleted=False).exclude(user=user).first()
        if not replacement:
            raise ValidationError({'transfer_to': 'Choose an active member to own the pod before leaving.'})
        task.goal.user_id = replacement.user_id
        task.goal.save(update_fields=['user', 'updated_at'])
        replacement.role = 'admin'
        replacement.save(update_fields=['role', 'updated_at'])
        GoalMembership.objects.filter(goal=task.goal, user=replacement.user).update(role='admin')
        audit(actor, 'task.ownership_transferred', task, reason, metadata={'owner_id': replacement.user_id})
    membership.state = 'removed' if remove_user else 'left'
    membership.left_at, membership.reason = timezone.now(), reason
    membership.feedback = feedback
    membership.save()
    membership.periods.filter(ended_at__isnull=True).update(ended_at=membership.left_at)
    GoalMembership.objects.filter(goal=task.goal, user=user).delete()
    ConversationMembership.objects.filter(conversation=task.goal.conversation, user=user).delete()
    audit(actor, 'task.member_removed' if remove_user else 'task.left', task, reason, metadata={'user_id': user.id})
    notify([user.id], 'community_pod_membership_changed', {'task_id': task.id, 'reason': reason, 'state': membership.state})
    return membership


@transaction.atomic
def set_task_status(task, actor, status, reason=''):
    task = CommunityTask.objects.select_for_update().select_related('goal').get(pk=task.pk)
    if not (can_manage_task(task, actor) or can_manage_group(task.group, actor)):
        raise PermissionDenied()
    if status not in ('active', 'completed', 'archived', 'cancelled', 'frozen', 'disabled', 'deleted'):
        raise ValidationError({'status': 'Invalid task status.'})
    if status in ('frozen', 'disabled', 'deleted', 'cancelled'):
        reason = require_reason(reason)
    previous_status = task.status
    today = timezone.now().astimezone(datetime_timezone.utc).date()
    owed_dates = task_due_dates(task, until=today) if previous_status == 'active' and status != 'active' else []
    if previous_status == 'active' and status != 'active':
        task.goal.checkins.filter(scheduled_for__gt=today, status='pending', submitted_at__isnull=True).filter(
            Q(evidence='') | Q(evidence__isnull=True)).delete()
    if status == 'active' and previous_status != 'active':
        last_resume = task.audit.filter(action='task.active').order_by('-id').first()
        stops = task.audit.filter(action__in=['task.frozen', 'task.disabled', 'task.completed', 'task.archived', 'task.cancelled', 'task.deleted'])
        if last_resume:
            stops = stops.filter(id__gt=last_resume.id)
        stopped = stops.order_by('id').first()
        stopped_on = (stopped.created_at if stopped else task.updated_at).astimezone(datetime_timezone.utc).date()
        task.goal.checkins.filter(scheduled_for__gt=stopped_on, status='pending', submitted_at__isnull=True).filter(
            Q(evidence='') | Q(evidence__isnull=True)).delete()
        task.checkin_schedule_effective_from = max(task.goal.start_date or today, today)
    task.status = 'archived' if status == 'deleted' else status
    task.save(update_fields=['status', 'checkin_schedule_effective_from', 'updated_at'])
    task.goal.is_active = task.status == 'active'
    task.goal.status = 'in_progress' if task.status == 'active' else task.status
    task.goal.save(update_fields=['is_active', 'status', 'updated_at'])
    audit(actor, 'task.' + status, task, reason, metadata={
        'previous_status': previous_status, 'checkin_due_dates': [due.isoformat() for due in owed_dates],
    })
    notify(task.memberships.filter(state='active').values_list('user_id', flat=True),
           'community_task_status_changed', {'task_id': task.id, 'goal_id': task.goal_id, 'status': task.status, 'reason': reason})
    if task.status == 'active':
        generate_task_cycles(task)
    elif status in ('completed', 'archived', 'deleted'):
        from .awards import award_closed_pod_checkins
        award_closed_pod_checkins(task, actor, closure_status=status)
    return task


def task_due_dates(task, until=None):
    start, end = task.goal.start_date, task.goal.target_date
    if not start or not end:
        return []
    if task.checkin_schedule_effective_from:
        start = max(start, task.checkin_schedule_effective_from)
    frequency = task.goal.checkin_frequency.upper()
    interval = {'DAILY': 1, '3-DAYS': 3, 'WEEKLY': 7, 'BI-WEEKLY': 14, 'CUSTOM': task.custom_interval_days}.get(frequency)
    if not interval:
        return []
    end = min(end, until) if until else end
    return [start + timedelta(days=offset) for offset in range(0, (end - start).days + 1, interval)]


def is_task_checkin_due(task, date):
    return date in task_due_dates(task, until=date)


def _notify_task_checkin(task, membership, checkin, event):
    if not membership.user.notify_on_reminders:
        return
    due = checkin.scheduled_for
    if not any(period.joined_at.astimezone(datetime_timezone.utc).date() <= due
               and (not period.ended_at or due <= period.ended_at.astimezone(datetime_timezone.utc).date())
               for period in membership.periods.all()):
        return
    labels = {
        'due': ('Check-in due', 'Your pod check-in is due today. Share an honest update, even if progress is partial or blocked.'),
        'reminder': ('Check-in reminder', 'Your pod check-in is still pending. Please check in before the UTC day ends.'),
        'missed': ('Missed check-in', f'Your pod check-in for {due.isoformat()} was not submitted before the UTC day ended.'),
    }
    title, message = labels[event]
    Notification.objects.get_or_create(
        user=membership.user, type='community_checkin_' + event, payload__checkin_id=checkin.pk,
        defaults={'payload': {'goal_id': task.goal_id, 'task_id': task.id, 'checkin_id': checkin.pk,
                              'due_date': due.isoformat(), 'title': title, 'message': message}},
    )


def _mark_task_checkin_missed(task, membership, checkin):
    changed = GoalCheckin.objects.filter(pk=checkin.pk, status='pending', submitted_at__isnull=True).update(status='missed')
    if changed:
        _notify_task_checkin(task, membership, checkin, 'missed')


@transaction.atomic
def generate_task_cycles(task, now=None):
    task = CommunityTask.objects.select_for_update().select_related('goal').get(pk=task.pk)
    now = now or timezone.now()
    utc_now = now.astimezone(datetime_timezone.utc)
    today = utc_now.date()
    if task.status != 'active' or not task.goal.is_active:
        return 0
    if task.invitation_deadline <= now:
        recipients = set(task.memberships.filter(state='active', role='admin').values_list('user_id', flat=True))
        recipients.update(task.invitations.filter(status='pending').values_list('user_id', flat=True))
        from django.contrib.auth import get_user_model
        for user_id in get_user_model().objects.filter(pk__in=recipients, is_active=True, deleted=False).values_list('id', flat=True):
            Notification.objects.get_or_create(user_id=user_id, type='community_invitation_closed',
                payload={'task_id': task.id, 'message': 'The task invitation deadline has passed.'})
    created_count = 0
    dates = task_due_dates(task, until=today + timedelta(days=1))
    pending_today = False
    for membership in task.memberships.filter(state='active', user__is_active=True, user__deleted=False).select_related('user').prefetch_related('periods'):
        # Previously issued cycles remain accountable even after a cadence edit.
        for previous in GoalCheckin.objects.filter(goal=task.goal, user=membership.user, scheduled_for__lt=today,
                                                  submitted_at__isnull=True, status='pending'):
            _mark_task_checkin_missed(task, membership, previous)
        for due in dates:
            if membership.joined_at and due < membership.joined_at.date():
                continue
            checkin, created = GoalCheckin.objects.get_or_create(goal=task.goal, user=membership.user, scheduled_for=due)
            created_count += int(created)
            if due < today and not checkin.submitted_at and checkin.status == 'pending':
                _mark_task_checkin_missed(task, membership, checkin)
            if due == today and checkin.status == 'pending' and not checkin.submitted_at:
                pending_today = True
                if membership.user.notify_on_reminders:
                    CheckinReminderLog.objects.get_or_create(goal=task.goal, user=membership.user,
                        reminder_for_date=due, defaults={'frequency': task.goal.checkin_frequency})
                    _notify_task_checkin(task, membership, checkin, 'due')
                    if utc_now.hour >= COMMUNITY_CHECKIN_REMINDER_HOUR_UTC:
                        _notify_task_checkin(task, membership, checkin, 'reminder')
    for due in dates:
        if due != today or not pending_today:
            continue
        if not Message.objects.filter(conversation=task.goal.conversation, kind='checkin', metadata__cycle_date=due.isoformat()).exists():
            # System prompts are not user activity or generic chat alerts; the
            # per-member notices above enforce reminder preferences and status.
            prompt = Message(conversation=task.goal.conversation, sender=task.goal.user, kind='checkin', text='Your scheduled check-in is ready.',
                             metadata={'goal_id': task.goal_id, 'cycle_date': due.isoformat(), 'event': 'checkin_due'})
            Message.objects.bulk_create([prompt])
            from .community_messaging import broadcast_message
            transaction.on_commit(lambda mid=prompt.pk, cid=prompt.conversation_id: broadcast_message(mid, cid, created=True))
    return created_count


def review_inactive_members(now=None):
    now = now or timezone.now()
    cutoff, flagged = now - timedelta(days=28), 0
    for model in (CommunityMembership, CommunityTaskMembership):
        for member in model.objects.filter(state='active', user__is_active=True, user__deleted=False).select_related('user'):
            last_login = member.user.last_login or member.user.created_at
            if last_login > cutoff:
                CommunityInactivityReview.objects.filter(user=member.user, resolved=False).update(resolved=True)
                continue
            scope = {'group': member.group} if isinstance(member, CommunityMembership) else {'task': member.task}
            _, created = CommunityInactivityReview.objects.get_or_create(user=member.user, last_login_at=last_login, **scope)
            if not created:
                continue
            flagged += 1
            admins = (member.group.memberships if isinstance(member, CommunityMembership) else member.task.memberships).filter(state='active', role='admin')
            payload = {'user_id': member.user_id, 'message': '28 days without login. Review this membership; removal requires an explicit admin decision.'}
            payload.update({key + '_id': value.id for key, value in scope.items()})
            notify([member.user_id, *admins.values_list('user_id', flat=True)], 'community_inactivity_review', payload)
    return flagged


@transaction.atomic
def resolve_inactivity_review(review, actor, decision, reason, transfer_to=None):
    review = CommunityInactivityReview.objects.select_for_update().get(pk=review.pk)
    if review.resolved:
        raise ValidationError('This inactivity review has already been resolved.')
    manager = can_manage_group(review.group, actor) if review.group_id else can_manage_task(review.task, actor)
    if not manager:
        raise PermissionDenied()
    reason = require_reason(reason)
    if decision == 'remove':
        if review.group_id:
            manage_group_member(review.group, actor, review.user, 'remove', reason=reason)
        else:
            leave_task(review.task, actor, reason, transfer_to=transfer_to, remove_user=review.user)
    elif decision != 'retain':
        raise ValidationError({'decision': 'Choose retain or remove.'})
    review.resolved = True
    review.save(update_fields=['resolved', 'updated_at'])
    audit(actor, 'membership.inactivity_' + decision, review, reason, group=review.group)
    return review
