"""Shared messaging policy for community REST, legacy REST and sockets."""

import json
import mimetypes
import re
from datetime import timedelta
from pathlib import PurePosixPath

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.apps import apps
from django.db import transaction
from django.db.models import Q
from django.http import FileResponse
from django.utils import timezone
from rest_framework import mixins, permissions, serializers, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.response import Response

from .message_models import (
    MessageHidden, MessagePin, MessagePoll, MessagePollOption, MessagePollVote,
    MessageReaction, RetainedMessageAttachment, RetainedMessageEvidence,
)
from .models import ContentReport, Conversation, GoalCheckin, Message, Notification, UserBlock


def policy():
    from . import community_access
    return community_access


def conversation_group(conversation):
    model = apps.get_model('api', 'CommunityGroup')
    return model.objects.filter(conversation_id=conversation.pk).first()


def visible_messages(queryset, user, resources=False):
    if not user or not user.is_authenticated or not user.is_active or getattr(user, 'deleted', False):
        return queryset.none()
    queryset = policy().visible_messages(queryset, user, resources=resources)
    blocked = UserBlock.objects.filter(Q(blocker=user) | Q(blocked=user))
    blocked_ids = [b.blocked_id if b.blocker_id == user.id else b.blocker_id for b in blocked]
    return queryset.exclude(hidden_for__user=user).exclude(sender_id__in=blocked_ids).exclude(
        Q(conversation__partnership__user_a_id__in=blocked_ids) | Q(conversation__partnership__user_b_id__in=blocked_ids)
    ).distinct()


def visible_resource_messages(queryset, user):
    return visible_messages(queryset, user, resources=True)


def can_moderate(message, user):
    if not user or not getattr(user, 'is_authenticated', False):
        return False
    if not policy().can_read_conversation(message.conversation, user):
        return False
    group = conversation_group(message.conversation)
    if group:
        membership = policy().group_membership(group, user)
        return bool(policy().is_internal(user) or (
            membership and membership.state == 'active' and membership.role in {'admin', 'moderator', 'owner'}
        ))
    task = getattr(message.conversation.goal, 'community_task', None) if message.conversation.goal_id else None
    if not task:
        return False
    membership = policy().task_membership(task, user)
    return bool(policy().is_internal(user) or (
        membership and membership.state == 'active' and membership.role == 'admin'
    ))


def can_sender_delete(message, user):
    return bool(
        user and getattr(user, 'is_authenticated', False)
        and message.sender_id == user.pk and (
            message.kind == Message.KIND_USER or (
                message.kind == Message.KIND_GOAL and message.metadata.get('event') == 'community_task_created'
            )
        )
        and not message.recalled_at
        and message.created_at >= timezone.now() - timedelta(minutes=15)
        and can_interact(message.conversation, user)
    )


def can_interact(conversation, user):
    if not policy().can_read_conversation(conversation, user):
        return False
    group = getattr(conversation, 'community_group', None)
    if group:
        membership = policy().group_membership(group, user)
        return group.status == 'active' and bool(policy().is_internal(user) or (membership and membership.state == 'active'))
    if conversation.goal_id:
        return policy().can_write_goal(conversation.goal, user)
    return True


def can_receive_updates(conversation, user):
    if not policy().can_read_conversation(conversation, user):
        return False
    group = getattr(conversation, 'community_group', None)
    if group:
        membership = policy().group_membership(group, user)
        return bool(policy().is_internal(user) or (membership and membership.state == 'active'))
    task = getattr(conversation.goal, 'community_task', None) if conversation.goal_id else None
    if task:
        membership = policy().task_membership(task, user)
        return bool(policy().is_internal(user) or (membership and membership.state == 'active'))
    return True


def can_review_checkin(checkin, user):
    if not user or checkin.user_id == user.pk or not checkin.submitted_at:
        return False
    if not policy().can_write_goal(checkin.goal, user):
        return False
    task = getattr(checkin.goal, 'community_task', None)
    membership = policy().task_membership(task, user) if task else None
    return not task or bool(membership and membership.state == 'active')


def _notification_in_membership_period(membership, created_at, group=False):
    if not membership or not created_at:
        return False
    for index, period in enumerate(membership.periods.order_by('joined_at', 'id')):
        start = period.joined_at - timedelta(days=30) if group and not index else period.joined_at
        if start <= created_at and (not period.ended_at or created_at <= period.ended_at):
            return True
    return False


def chat_notification_allowed(message, user):
    if not can_receive_updates(message.conversation, user) or not user.notify_on_new_message:
        return False
    group = getattr(message.conversation, 'community_group', None)
    membership = policy().group_membership(group, user) if group else None
    if membership and membership.notifications_muted:
        return False
    return not message.recalled_at and visible_messages(Message.objects.filter(pk=message.pk), user).exists()


CHECKIN_NOTIFICATION_TYPES = frozenset({
    'community_checkin_submitted', 'community_checkin_reviewed',
    'community_checkin_due', 'community_checkin_reminder', 'community_checkin_missed',
})


def checkin_notification_data(checkin, notification_type):
    from .serializers import PublicUserSerializer
    author = PublicUserSerializer(checkin.user).data
    reviewer = PublicUserSerializer(checkin.reviewer).data if checkin.reviewer_id else None
    titles = {
        'community_checkin_submitted': 'New pod check-in',
        'community_checkin_reviewed': 'Check-in confirmed' if checkin.review_status == 'confirmed' else 'Check-in needs clarification',
        'community_checkin_due': 'Your pod check-in is ready',
        'community_checkin_reminder': 'Pod check-in reminder',
        'community_checkin_missed': 'Missed pod check-in',
    }
    messages = {
        'community_checkin_submitted': f'{author["name"]} submitted a check-in.',
        'community_checkin_reviewed': 'Your check-in was confirmed.' if checkin.review_status == 'confirmed' else 'A pod member requested clarification on your check-in.',
        'community_checkin_due': 'Your scheduled pod check-in is ready.',
        'community_checkin_reminder': 'Your scheduled pod check-in is awaiting your update.',
        'community_checkin_missed': 'You missed a scheduled pod check-in. You can still submit an update.',
    }
    return {'goal_id': checkin.goal_id, 'task_id': checkin.goal.community_task.pk,
            'checkin_id': checkin.pk, 'due_date': checkin.scheduled_for.isoformat(),
            'status': checkin.status, 'review_status': checkin.review_status,
            'submitted_by': author, 'reviewer': reviewer, 'reviewer_id': checkin.reviewer_id,
            'title': titles[notification_type], 'message': messages[notification_type]}


@transaction.atomic
def notify_checkin_event(checkin, actor, *, reviewed=False):
    task = getattr(checkin.goal, 'community_task', None)
    if not task:
        return
    recipients = task.memberships.filter(state='active', user__is_active=True, user__deleted=False,
                                          user__notify_on_reminders=True).exclude(user=actor)
    if reviewed:
        recipients = recipients.filter(user_id=checkin.user_id)
    else:
        recipients = recipients.exclude(user_id=checkin.user_id)
    notification_type = 'community_checkin_reviewed' if reviewed else 'community_checkin_submitted'
    payload = checkin_notification_data(checkin, notification_type)
    for user_id in recipients.values_list('user_id', flat=True):
        Notification.objects.get_or_create(user_id=user_id, type=notification_type, payload=payload)


def notification_payload(notification, user=None, *, delivery=False):
    """Rebuild scoped previews rather than trusting stored notification snapshots."""
    user = user or notification.user
    if not policy().active_user(user) or notification.user_id != user.pk:
        return None
    payload = notification.payload if isinstance(notification.payload, dict) else {}
    if notification.type in CHECKIN_NOTIFICATION_TYPES:
        checkin_id = payload.get('checkin_id')
        if not str(checkin_id or '').isdigit():
            return None
        checkin = GoalCheckin.objects.select_related('goal__community_task', 'user', 'reviewer').filter(pk=checkin_id).first()
        task = getattr(checkin.goal, 'community_task', None) if checkin else None
        if not task or str(payload.get('goal_id')) != str(checkin.goal_id) or str(payload.get('task_id')) != str(task.pk):
            return None
        membership = policy().task_membership(task, user)
        if not membership or membership.state != 'active' or not _notification_in_membership_period(membership, notification.created_at):
            return None
        if notification.type == 'community_checkin_submitted':
            if not checkin.submitted_at or user.pk == checkin.user_id:
                return None
        elif notification.type == 'community_checkin_reviewed':
            if user.pk != checkin.user_id or not checkin.reviewer_id or user.pk == checkin.reviewer_id:
                return None
        else:
            if user.pk != checkin.user_id:
                return None
            if delivery and (task.status != 'active' or checkin.submitted_at or checkin.status not in {'pending', 'missed'}):
                return None
        return checkin_notification_data(checkin, notification.type)
    own_notice_types = {
        'community_membership_changed', 'community_pod_membership_changed',
        'community_invitation', 'community_task_invitation', 'community_invitation_closed',
        'community_join_decision', 'community_task_join_decision',
        'community_creation_permission', 'community_account_notice',
    }
    if notification.type in own_notice_types:
        allowed_keys = {'group_id', 'task_id', 'goal_id', 'invitation_id', 'role', 'state', 'action',
                        'reason', 'decision', 'approved', 'title', 'message'}
        result = {key: value for key, value in payload.items() if key in allowed_keys}
        if notification.type in {'community_membership_changed', 'community_pod_membership_changed'}:
            result.pop('title', None)
            result['message'] = 'Your pod membership has changed.' if notification.type == 'community_pod_membership_changed' else 'Your community membership or role has changed.'
        return result

    if 'message_id' in payload:
        try:
            message_id = int(payload['message_id'])
        except (TypeError, ValueError):
            return None
        message = visible_messages(Message.objects.filter(pk=message_id), user).select_related('conversation', 'sender').first()
        if not message:
            return None
        if delivery and not chat_notification_allowed(message, user):
            return None
        group = getattr(message.conversation, 'community_group', None)
        task = getattr(message.conversation.goal, 'community_task', None) if message.conversation.goal_id else None
        group_member = policy().group_membership(group, user) if group else None
        if group_member and group_member.notifications_muted:
            return None
        if not policy().is_internal(user):
            member = group_member if group else policy().task_membership(task, user) if task else None
            if member and not _notification_in_membership_period(member, notification.created_at, group=bool(group)):
                return None
        text = message.text.strip()
        if message.recalled_at:
            text = 'This message was removed by a moderator' if message.deletion_kind == 'moderator' else 'This message was deleted'
        elif len(text) > 160:
            text = text[:157] + '...'
        result = {'conversation_id': message.conversation_id, 'message_id': message.pk,
                  'sender_id': message.sender_id, 'sender_name': message.sender.name, 'preview': text}
        if group:
            result['group_id'] = group.pk
        elif message.conversation.goal_id:
            result['goal_id'] = message.conversation.goal_id
        return result

    if 'conversation_id' in payload or notification.type in {'new_message', 'message_reply', 'message_mention', 'message_reaction', 'poll_vote', 'message_pinned'}:
        conversation_id = payload.get('conversation_id')
        conversation = Conversation.objects.filter(pk=conversation_id).first() if str(conversation_id or '').isdigit() else None
        if conversation and not policy().can_read_conversation(conversation, user):
            return None
        if conversation and not policy().is_internal(user):
            group = getattr(conversation, 'community_group', None)
            task = getattr(conversation.goal, 'community_task', None) if conversation.goal_id else None
            member = policy().group_membership(group, user) if group else policy().task_membership(task, user) if task else None
            if member and not _notification_in_membership_period(member, notification.created_at, group=bool(group)):
                return None
            if group and member and member.notifications_muted:
                return None
        if delivery and conversation:
            if not can_receive_updates(conversation, user):
                return None
            group = getattr(conversation, 'community_group', None)
            membership = policy().group_membership(group, user) if group else None
            if membership and membership.notifications_muted:
                return None
        # Unlinked legacy alerts can remain generic, but cannot expose old bodies,
        # attachments or reply snapshots whose message authorization is unknown.
        result = {key: payload[key] for key in ('conversation_id', 'sender_name') if key in payload}
        if conversation:
            group = getattr(conversation, 'community_group', None)
            if group:
                result['group_id'] = group.pk
            elif conversation.goal_id:
                result['goal_id'] = conversation.goal_id
        return result

    from .community_models import CommunityGroup, CommunityTask
    if notification.type == 'community_task_created':
        group_id = payload.get('group_id')
        group = CommunityGroup.objects.filter(pk=group_id).first() if str(group_id or '').isdigit() else None
        if not group or not policy().can_read_group(group, user):
            return None
        member = policy().group_membership(group, user)
        if member and member.notifications_muted:
            return None
        if not policy().is_internal(user) and (
            not _notification_in_membership_period(member, notification.created_at, group=True)
            or (delivery and member.state != 'active')
        ):
            return None
        return {key: value for key, value in payload.items() if key in {'group_id', 'task_id', 'goal_id', 'title', 'message'}}
    goal = None
    task_id = payload.get('task_id') if notification.type.startswith('community_') else None
    if str(task_id or '').isdigit():
        task = CommunityTask.objects.filter(pk=task_id).select_related('goal').first()
        goal = task.goal if task else None
    if goal is None and str(payload.get('goal_id') or '').isdigit():
        from .models import Goal
        goal = Goal.objects.filter(pk=payload['goal_id']).first()
    if goal:
        if not policy().can_access_goal(goal, user):
            return None
        task = getattr(goal, 'community_task', None)
        if task and not policy().is_internal(user):
            membership = policy().task_membership(task, user)
            if not _notification_in_membership_period(membership, notification.created_at):
                return None
            if delivery and membership.state != 'active':
                return None
        return dict(payload)
    group_id = payload.get('group_id')
    if str(group_id or '').isdigit():
        group = CommunityGroup.objects.filter(pk=group_id).first()
        if not group or not policy().can_read_group(group, user):
            return None
        if not policy().is_internal(user):
            membership = policy().group_membership(group, user)
            if not _notification_in_membership_period(membership, notification.created_at, group=True):
                return None
            if delivery and membership.state != 'active':
                return None
    return dict(payload)


def audit(actor, action_name, target, reason, group=None, metadata=None):
    from .community_services import audit as record_audit
    return record_audit(actor, action_name, target, reason, group=group, metadata=metadata or {})


PREVIEW_CONTENT_TYPES = frozenset({
    'image/png', 'image/jpeg', 'image/gif', 'image/webp', 'image/avif', 'image/bmp',
    'video/mp4', 'video/webm', 'video/ogg', 'video/mpeg', 'video/quicktime',
    'audio/mpeg', 'audio/mp4', 'audio/ogg', 'audio/wav', 'audio/x-wav',
    'audio/webm', 'audio/flac', 'audio/x-flac', 'audio/aac', 'audio/x-m4a', 'application/pdf',
})
DOWNLOAD_CONTENT_TYPES = frozenset({
    'text/plain', 'text/csv', 'application/zip', 'application/gzip', 'application/x-tar',
    'application/msword', 'application/vnd.ms-excel', 'application/vnd.ms-powerpoint',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'application/vnd.oasis.opendocument.text', 'application/vnd.oasis.opendocument.spreadsheet',
    'application/vnd.oasis.opendocument.presentation',
})


def safe_file_name(name):
    return PurePosixPath(str(name).replace('\\', '/')).name


def safe_file_mime(filename, mime=None):
    guessed, encoding = mimetypes.guess_type(filename)
    mime = (mime or guessed or '').split(';', 1)[0].strip().lower()
    active_extensions = {'.html', '.htm', '.shtml', '.xhtml', '.svg', '.svgz', '.xml', '.xsl', '.xslt', '.js', '.mjs'}
    if encoding or PurePosixPath(filename).suffix.lower() in active_extensions:
        return 'application/octet-stream'
    return mime if mime in PREVIEW_CONTENT_TYPES | DOWNLOAD_CONTENT_TYPES else 'application/octet-stream'


def protected_response(field, filename, mime=None, *, as_attachment=True):
    filename = safe_file_name(filename)
    mime = safe_file_mime(filename, mime)
    as_attachment = as_attachment or mime not in PREVIEW_CONTENT_TYPES
    try:
        response = FileResponse(field.open('rb'), as_attachment=as_attachment, filename=filename, content_type=mime)
    except (FileNotFoundError, OSError):
        from rest_framework.exceptions import NotFound
        raise NotFound('This file is no longer available.')
    response['Cache-Control'] = 'private, no-store, max-age=0'
    response['Pragma'] = 'no-cache'
    response['X-Content-Type-Options'] = 'nosniff'
    response['Content-Security-Policy'] = "sandbox; default-src 'none'"
    return response


def attachment_url(message, request=None):
    if message.recalled_at or not message.attachment:
        return None
    path = f'/api-v1/community/messages/{message.pk}/attachment/'
    return request.build_absolute_uri(path) if request else path


def broadcast_message(message_id, conversation_id, created=False):
    layer = get_channel_layer()
    if not layer:
        return
    # Send only an ID: each socket rechecks access and serializes for its recipient.
    async_to_sync(layer.group_send)(f'chat_{conversation_id}', {
        'type': 'chat.message' if created else 'chat.message.updated',
        'message_id': message_id,
    })
    conversation = Conversation.objects.get(pk=conversation_id)
    for uid in conversation.members.values_list('id', flat=True):
        async_to_sync(layer.group_send)(f'conversations_user_{uid}', {
            'type': 'conversations.update', 'conversation_id': conversation_id,
        })


def report_is_unresolved(message):
    if ContentReport.objects.filter(message=message, status__in=['pending', 'reviewed']).exists():
        return True
    model = apps.get_model('api', 'CommunityReport')
    names = {f.name for f in model._meta.fields}
    if 'message' in names:
        return model.objects.filter(message=message).exclude(status__in=['resolved', 'dismissed', 'actioned']).exists()
    if {'target_type', 'target_id'} <= names:
        return model.objects.filter(target_type='message', target_id=message.pk).exclude(status__in=['resolved', 'dismissed', 'actioned']).exists()
    return False


def retain_message_evidence(message):
    from .community_models import CommunityReport
    from .serializers import MessageSerializer
    data = MessageSerializer(message).data
    message_keys = {'id', 'conversation', 'sender', 'text', 'kind', 'metadata', 'poll', 'reactions',
                    'attachment_name', 'attachment_mime', 'attachment_size', 'created_at', 'updated_at'}
    reports = []
    for report in ContentReport.objects.filter(message=message, status__in=['pending', 'reviewed']):
        reports.append({'type': 'content', 'id': report.pk, 'reporter_id': report.reporter_id,
                        'reason': report.reason, 'details': report.details, 'status': report.status,
                        'created_at': report.created_at.isoformat()})
    for report in CommunityReport.objects.filter(message=message).exclude(status__in=['resolved', 'dismissed', 'actioned']):
        reports.append({'type': 'community', 'id': report.pk, 'reporter_id': report.reporter_id,
                        'reason': report.reason, 'details': report.details, 'status': report.status,
                        'created_at': report.created_at.isoformat()})
    return RetainedMessageEvidence.objects.get_or_create(message=message, defaults={
        'snapshot': {'message': {key: value for key, value in data.items() if key in message_keys}, 'reports': reports},
    })[0]


@transaction.atomic
def cleanup_retained_attachments(message_ids=None):
    """Purge resolved report snapshots and delete their files only after commit."""
    ids = set(RetainedMessageAttachment.objects.values_list('message_id', flat=True))
    ids.update(RetainedMessageEvidence.objects.values_list('message_id', flat=True))
    if message_ids is not None:
        ids.intersection_update(message_ids)
    for message in Message.objects.select_for_update().filter(pk__in=ids).order_by('pk'):
        if report_is_unresolved(message):
            continue
        hold = RetainedMessageAttachment.objects.filter(message=message).first()
        if hold:
            storage, name = hold.file.storage, hold.file.name
            hold.delete()
            transaction.on_commit(lambda s=storage, n=name: s.delete(n))
        RetainedMessageEvidence.objects.filter(message=message).delete()


@transaction.atomic
def set_report_review(report, actor, status, notes='', reason=''):
    """Synchronize both report surfaces before releasing private evidence holds."""
    from .community_models import CommunityReport
    status = serializers.ChoiceField(choices=['pending', 'reviewed', 'actioned', 'dismissed']).run_validation(status)
    notes = serializers.CharField(allow_blank=True, max_length=10000).run_validation(notes)
    message_id = report.message_id
    if not message_id and isinstance(report, CommunityReport) and report.content_report_id:
        message_id = ContentReport.objects.filter(pk=report.content_report_id).values_list('message_id', flat=True).first()
    if message_id:
        Message.objects.select_for_update().get(pk=message_id)
    if isinstance(report, ContentReport):
        original = ContentReport.objects.select_for_update().get(pk=report.pk)
        mirror = CommunityReport.objects.select_for_update().filter(content_report=original).first()
    else:
        original = ContentReport.objects.select_for_update().filter(pk=report.content_report_id).first()
        mirror = CommunityReport.objects.select_for_update().get(pk=report.pk)
    group = mirror.group if mirror else conversation_group(original.conversation) if original and original.conversation_id else None
    if not policy().is_internal(actor) and not (group and policy().can_moderate_group(group, actor)):
        raise PermissionDenied('Only authorized report reviewers can change this report.')
    if original:
        original.status, original.moderator_notes = status, notes
        original.save(update_fields=['status', 'moderator_notes', 'updated_at'])
    if mirror:
        mirror.status, mirror.notes, mirror.reviewer, mirror.reviewed_at = status, notes, actor, timezone.now()
        mirror.save(update_fields=['status', 'notes', 'reviewer', 'reviewed_at', 'updated_at'])
    result = original if isinstance(report, ContentReport) else mirror
    audit(actor, 'report.' + status, result, str(reason or notes or f'Report marked {status}.'), group=group)
    cleanup_retained_attachments(message_ids=[message_id] if message_id else [])
    return result


@transaction.atomic
def delete_selection(user, ids, scope, reason=''):
    if scope not in {'me', 'everyone'}:
        raise ValidationError({'scope': 'Use me or everyone.'})
    if not isinstance(ids, list) or not ids or len(ids) > 100 or any(type(i) is not int for i in ids):
        raise ValidationError({'ids': 'Select between 1 and 100 message IDs.'})
    ids = list(dict.fromkeys(ids))
    # Lock before the visibility query: PostgreSQL disallows FOR UPDATE with DISTINCT.
    locked = list(Message.objects.select_for_update().select_related('conversation', 'sender').filter(pk__in=ids).order_by('pk'))
    visible_ids = set(visible_messages(Message.objects.filter(pk__in=ids), user).values_list('pk', flat=True))
    report_targets = {message.pk for message in locked if scope == 'everyone' and
                      (policy().is_internal(user) or can_moderate(message, user)) and report_is_unresolved(message)}
    moderation_targets = {message.pk for message in locked if scope == 'everyone' and can_moderate(message, user)}
    visible_ids |= report_targets | moderation_targets
    messages = [message for message in locked if message.pk in visible_ids]
    if len(messages) != len(ids):
        raise PermissionDenied('Every selected message must be visible to you.')
    if scope == 'me':
        MessageHidden.objects.bulk_create([MessageHidden(user=user, message=m) for m in messages], ignore_conflicts=True)
        layer = get_channel_layer()
        if layer:
            for conversation_id in {message.conversation_id for message in messages}:
                hidden_ids = [message.pk for message in messages if message.conversation_id == conversation_id]
                transaction.on_commit(lambda cid=conversation_id, mids=hidden_ids: async_to_sync(layer.group_send)(
                    f'chat_{cid}', {'type': 'chat.messages.hidden', 'user_id': user.pk, 'ids': mids}))
        return
    reason = str(reason or '').strip()
    for message in messages:
        if message.recalled_at or not (can_sender_delete(message, user) or can_moderate(message, user) or message.pk in report_targets):
            raise PermissionDenied('Every selected message must be eligible for deletion for everyone.')
        if not can_sender_delete(message, user) and not reason:
            raise ValidationError({'reason': 'A moderation reason is required.'})
    for message in messages:
        moderation = not can_sender_delete(message, user)
        unresolved = report_is_unresolved(message)
        if unresolved:
            retain_message_evidence(message)
        if message.attachment:
            storage, name = message.attachment.storage, message.attachment.name
            if unresolved:
                RetainedMessageAttachment.objects.create(
                    message=message, file=name, filename=message.attachment_name, mime=message.attachment_mime,
                )
            else:
                transaction.on_commit(lambda s=storage, n=name: s.delete(n))
        message.recalled_at = timezone.now()
        message.deletion_kind = 'moderator' if moderation else 'sender'
        message.deleted_by = user
        message.deletion_reason = reason if moderation else ''
        message.text = ''
        message.attachment = None
        message.attachment_name = ''
        message.attachment_mime = ''
        message.attachment_size = None
        message.metadata = {}
        message.save()
        MessagePin.objects.filter(message=message).delete()
        MessageReaction.objects.filter(message=message).delete()
        MessagePoll.objects.filter(message=message).delete()
        task = getattr(message.conversation.goal, 'community_task', None) if message.conversation.goal_id else None
        audit(user, 'message_removed' if moderation else 'message_deleted', message,
              reason if moderation else 'Sender deleted their message.', conversation_group(message.conversation),
              metadata={'conversation_id': message.conversation_id, 'goal_id': message.conversation.goal_id,
                        'community_task_id': task.pk if task else None})
        transaction.on_commit(lambda mid=message.pk, cid=message.conversation_id: broadcast_message(mid, cid))


def post_types(text='', attachment=None, poll=None):
    types = []
    if text:
        if 'https://' in text or 'http://' in text:
            if not re.fullmatch(r'\s*(?:https?://[^\s<>"\x27]+\s*)+', text):
                types.append('text')
            types.append('link')
        else:
            types.append('text')
    if attachment:
        mime = (getattr(attachment, 'content_type', '') or '').lower()
        types.append('image' if mime.startswith('image/') else 'video' if mime.startswith('video/') else 'document')
    if poll:
        types.append('poll')
    return types or ['text']


def assert_post_allowed(conversation, user, text='', attachment=None, poll=None):
    for post_type in post_types(text, attachment, poll):
        if not policy().can_write_conversation(conversation, user, post_type=post_type):
            raise PermissionDenied('Posting this content is not permitted in this conversation.')


class CommunityMessageViewSet(mixins.CreateModelMixin, mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [JSONParser, MultiPartParser, FormParser]

    def get_serializer_class(self):
        from .serializers import MessageSerializer
        return MessageSerializer

    def get_queryset(self):
        qs = visible_messages(Message.objects.select_related('sender', 'conversation', 'reply_to_message__sender')
                              .prefetch_related('reactions__user', 'poll__options__votes__user'), self.request.user)
        conversation = self.request.query_params.get('conversation')
        if conversation:
            conversation = serializers.IntegerField(min_value=1).run_validation(conversation)
            qs = qs.filter(conversation_id=conversation)
        return qs.order_by('-created_at', '-id')

    @transaction.atomic
    def perform_create(self, serializer):
        values = serializer.validated_data
        conversation = values['conversation']
        assert_post_allowed(conversation, self.request.user, values.get('text', ''), values.get('attachment'), values.get('poll'))
        message = serializer.save(sender=self.request.user)
        transaction.on_commit(lambda: broadcast_message(message.pk, conversation.pk, created=True))

    @action(detail=False, methods=['post'], url_path='delete-selection')
    def delete_selected(self, request):
        ids, scope = request.data.get('ids'), request.data.get('scope')
        delete_selection(request.user, ids, scope, request.data.get('reason', ''))
        return Response({'ids': list(dict.fromkeys(ids)), 'scope': scope})

    def _writable_message(self):
        message = self.get_object()
        if message.recalled_at:
            raise ValidationError('This message was deleted.')
        if not can_interact(message.conversation, self.request.user):
            raise PermissionDenied('This conversation is read-only.')
        return message

    @action(detail=True, methods=['post'])
    def react(self, request, pk=None):
        message = self._writable_message()
        emoji = str(request.data.get('emoji', '')).strip()
        if not emoji or len(emoji) > 32:
            raise ValidationError({'emoji': 'Supply an emoji of at most 32 characters.'})
        reaction, created = MessageReaction.objects.get_or_create(message=message, user=request.user, emoji=emoji)
        if not created:
            reaction.delete()
        broadcast_message(message.pk, message.conversation_id)
        message.refresh_from_db()
        return Response(self.get_serializer(message).data)

    @action(detail=True, methods=['post'])
    def pin(self, request, pk=None):
        message = self._writable_message()
        value = request.data.get('pinned')
        if type(value) is not bool:
            raise ValidationError({'pinned': 'Supply a boolean.'})
        if value:
            MessagePin.objects.update_or_create(message=message, defaults={'pinned_by': request.user})
        else:
            MessagePin.objects.filter(message=message).delete()
        broadcast_message(message.pk, message.conversation_id)
        message.refresh_from_db()
        return Response(self.get_serializer(message).data)

    @action(detail=True, methods=['post'])
    @transaction.atomic
    def vote(self, request, pk=None):
        message = self._writable_message()
        poll = MessagePoll.objects.select_for_update().filter(message=message).first()
        if not poll:
            raise ValidationError('This message has no poll.')
        ids = request.data.get('option_ids')
        if not isinstance(ids, list) or any(type(i) is not int for i in ids):
            raise ValidationError({'option_ids': 'Supply option IDs.'})
        ids = list(dict.fromkeys(ids))
        if not poll.multiple_answers and len(ids) > 1:
            raise ValidationError({'option_ids': 'Only one option can be selected.'})
        if poll.options.filter(pk__in=ids).count() != len(ids):
            raise ValidationError({'option_ids': 'Every option must belong to this poll.'})
        MessagePollVote.objects.filter(option__poll=poll, user=request.user).delete()
        MessagePollVote.objects.bulk_create([MessagePollVote(option_id=i, user=request.user) for i in ids])
        transaction.on_commit(lambda: broadcast_message(message.pk, message.conversation_id))
        message.refresh_from_db()
        return Response(self.get_serializer(message).data)

    @action(detail=True, methods=['post'])
    def report(self, request, pk=None):
        message = self.get_object()
        reason = str(request.data.get('reason', '')).strip()
        if not reason:
            raise ValidationError({'reason': 'A reason is required.'})
        ContentReport.objects.create(reporter=request.user, reported_user=message.sender, message=message,
                                     conversation=message.conversation, reason=reason if reason in dict(ContentReport.REASON_CHOICES) else 'other',
                                     details=str(request.data.get('details', '')))
        return Response({'detail': 'Report submitted.'}, status=201)

    @action(detail=True, methods=['get'])
    def attachment(self, request, pk=None):
        # Resource history may precede the chat window, but never bypass an exit/removal.
        qs = visible_messages(Message.objects.select_related('conversation'), request.user, resources=True)
        message = qs.filter(pk=pk, recalled_at__isnull=True).first()
        if not message or not message.attachment:
            from rest_framework.exceptions import NotFound
            raise NotFound('No attachment is available.')
        return protected_response(message.attachment, message.attachment_name, message.attachment_mime)

    @action(detail=True, methods=['get'], url_path='retained-attachment')
    def retained_attachment(self, request, pk=None):
        if not policy().is_internal(request.user):
            raise PermissionDenied('Internal administrator access is required.')
        hold = RetainedMessageAttachment.objects.filter(message_id=pk).select_related('message').first()
        if not hold or not report_is_unresolved(hold.message):
            from rest_framework.exceptions import NotFound
            raise NotFound('No retained report evidence is available.')
        return protected_response(hold.file, hold.filename, hold.mime)

    @action(detail=True, methods=['get'], url_path='report-evidence')
    def report_evidence(self, request, pk=None):
        if not policy().is_internal(request.user):
            raise PermissionDenied('Internal administrator access is required.')
        message = Message.objects.select_related('sender', 'conversation').filter(pk=pk).first()
        if not message or not report_is_unresolved(message):
            from rest_framework.exceptions import NotFound
            raise NotFound('No unresolved report evidence is available.')
        hold = RetainedMessageAttachment.objects.filter(message=message).first() if message.recalled_at else None
        field = hold.file if hold else message.attachment if not message.recalled_at else None
        filename = hold.filename if hold else message.attachment_name
        mime = hold.mime if hold else message.attachment_mime
        if request.query_params.get('file') == '1':
            if not field:
                from rest_framework.exceptions import NotFound
                raise NotFound('No report attachment is available.')
            return protected_response(field, filename, mime)
        data = self.get_serializer(message).data
        snapshot = RetainedMessageEvidence.objects.filter(message=message).first()
        if snapshot:
            data.update(snapshot.snapshot['message'])
            data['reports'] = snapshot.snapshot['reports']
            data['evidence_captured_at'] = snapshot.created_at.isoformat()
        data['is_retained_evidence'] = bool(snapshot)
        # Access is to this reported target only, never its private reply/context.
        data['reply_to'] = None
        data['attachment'] = request.build_absolute_uri(f'/api-v1/community/messages/{message.pk}/report-evidence/?file=1') if field else None
        data['attachment_name'] = safe_file_name(filename) if field else ''
        data['attachment_mime'] = safe_file_mime(filename, mime) if field else ''
        data['can_moderate'] = not bool(message.recalled_at)
        data['can_delete_everyone'] = not bool(message.recalled_at)
        return Response(data, headers={
            'Cache-Control': 'private, no-store, max-age=0', 'Pragma': 'no-cache',
            'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "sandbox; default-src 'none'",
        })
