from __future__ import annotations

import logging

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.conf import settings
from django.db import transaction
from django.db.models.signals import post_save
from django.dispatch import receiver

from padluppcore.utils.email import EmailSendError, send_mailgun_email

from .activity import record_user_activity
from .models import Conversation, ConversationMembership, Evidence, Goal, GoalMembership, Message, Notification, Task, TimerSession
from .serializers import MessageSerializer

logger = logging.getLogger(__name__)


def _conversation_participant_ids(conversation: Conversation) -> list[int]:
    ids = list(conversation.members.values_list('id', flat=True))
    if ids:
        return ids
    if conversation.partnership_id:
        return [conversation.partnership.user_a_id, conversation.partnership.user_b_id]
    if conversation.goal_id:
        return list(conversation.goal.members.values_list('id', flat=True))
    return []


def _broadcast_conversation_state(conversation_id: int):
    try:
        channel_layer = get_channel_layer()
        if not channel_layer:
            return

        conv = Conversation.objects.select_related('partnership', 'goal').prefetch_related('members').get(id=conversation_id)
        user_ids = _conversation_participant_ids(conv)
        if not user_ids:
            return

        last_msg = (
            Message.objects.select_related('sender')
            .filter(conversation_id=conv.id)
            .order_by('-created_at')
            .first()
        )
        last_message_payload = MessageSerializer(last_msg, context={}).data if last_msg else None
        member_names = [u.name for u in conv.members.all()]

        for uid in user_ids:
            partner_name = None
            partner_avatar = None
            if conv.is_group and conv.goal_id:
                partner_name = conv.goal.title
            elif conv.partnership_id:
                partner_user = conv.partnership.user_b if conv.partnership.user_a_id == uid else conv.partnership.user_a
                partner_name = getattr(partner_user, 'name', None)
                partner_avatar = getattr(getattr(partner_user, 'avatar', None), 'url', None)
            else:
                partner_name = conv.goal.title if conv.goal_id else ', '.join(member_names)

            unread_count = (
                Message.objects.filter(conversation_id=conv.id, is_read=False)
                .exclude(sender_id=uid)
                .count()
            )
            payload = {
                'id': conv.id,
                'partnership': conv.partnership_id,
                'goal': conv.goal_id,
                'is_group': conv.is_group,
                'partner_name': partner_name,
                'partner_avatar': partner_avatar,
                'display_name': partner_name,
                'member_ids': user_ids,
                'member_names': member_names,
                'last_message': last_message_payload,
                'unread_count': unread_count,
                'created_at': conv.created_at.isoformat() if conv.created_at else None,
                'updated_at': conv.updated_at.isoformat() if conv.updated_at else None,
            }
            async_to_sync(channel_layer.group_send)(
                f'conversations_user_{uid}',
                {'type': 'conversations.update', 'payload': payload},
            )
    except Exception:
        logger.exception('Failed to broadcast conversation websocket update')


@receiver(post_save, sender=TimerSession)
def record_timer_session_activity(sender, instance: TimerSession, created: bool, **kwargs):
    if not created or not instance.user_id:
        return
    record_user_activity(instance.user, at=instance.started_at or instance.created_at, source='timer_session')


@receiver(post_save, sender=Evidence)
def record_evidence_activity(sender, instance: Evidence, created: bool, **kwargs):
    if not created or not instance.submitted_by_id:
        return
    record_user_activity(instance.submitted_by, at=instance.submitted_at or instance.created_at, source='evidence_submitted')


@receiver(post_save, sender=Message)
def record_message_activity(sender, instance: Message, created: bool, **kwargs):
    if not created or not instance.sender_id:
        return
    record_user_activity(instance.sender, at=instance.created_at, source='message_sent')


@receiver(post_save, sender=Goal)
def record_goal_activity(sender, instance: Goal, created: bool, **kwargs):
    # Match existing streak semantics: shared goal changes count for both partners.
    at = instance.updated_at or instance.created_at

    if instance.user_id:
        record_user_activity(instance.user, at=at, source='goal_updated')

    partnership = getattr(instance, 'partnership', None)
    if not partnership:
        return

    if getattr(partnership, 'user_a_id', None):
        record_user_activity(partnership.user_a, at=at, source='goal_updated')
    if getattr(partnership, 'user_b_id', None):
        record_user_activity(partnership.user_b, at=at, source='goal_updated')


@receiver(post_save, sender=Goal)
def sync_goal_members(sender, instance: Goal, created: bool, **kwargs):
    goal = Goal.objects.select_related('user', 'partnership', 'partnership__user_a', 'partnership__user_b').get(id=instance.id)
    member_users = {}
    if goal.user_id:
        member_users[goal.user_id] = goal.user
    if goal.partnership_id:
        if goal.partnership.user_a_id:
            member_users[goal.partnership.user_a_id] = goal.partnership.user_a
        if goal.partnership.user_b_id:
            member_users[goal.partnership.user_b_id] = goal.partnership.user_b
    for member in member_users.values():
        GoalMembership.objects.get_or_create(goal=goal, user=member, defaults={'added_by': goal.user})
    if goal.partnership_id and not goal.is_shared:
        Goal.objects.filter(id=goal.id, is_shared=False).update(is_shared=True)


@receiver(post_save, sender=GoalMembership)
def sync_goal_group_conversation(sender, instance: GoalMembership, created: bool, **kwargs):
    if not created:
        return
    goal = Goal.objects.select_related('user').prefetch_related('members').get(id=instance.goal_id)
    member_ids = list(goal.members.values_list('id', flat=True))
    if goal.user_id and goal.user_id not in member_ids:
        member_ids.append(goal.user_id)
    member_ids = list(dict.fromkeys(member_ids))
    if len(member_ids) < 2:
        return

    conversation, _ = Conversation.objects.get_or_create(goal=goal, defaults={'is_group': True})
    if not conversation.is_group:
        conversation.is_group = True
        conversation.save(update_fields=['is_group', 'updated_at'])

    for member_id in member_ids:
        ConversationMembership.objects.get_or_create(
            conversation=conversation,
            user_id=member_id,
            defaults={'added_by_id': instance.added_by_id or goal.user_id},
        )

    if not goal.is_shared:
        Goal.objects.filter(id=goal.id, is_shared=False).update(is_shared=True)
    _broadcast_conversation_state(conversation.id)


@receiver(post_save, sender=Task)
def record_task_completion_activity(sender, instance: Task, created: bool, **kwargs):
    if instance.status != Task.STATUS_COMPLETED or not instance.owner_id:
        return
    record_user_activity(instance.owner, at=instance.updated_at or instance.created_at, source='task_completed')


@receiver(post_save, sender=Conversation)
def broadcast_conversation_created(sender, instance: Conversation, created: bool, **kwargs):
    """Broadcast new conversations to each participant's conversations websocket.

    This ensures the conversations list updates no matter how the Conversation was
    created (REST, admin, scripts, etc.).
    """

    if not created:
        return

    def _send_after_commit():
        # Seed membership rows from the linked partnership or goal, then broadcast.
        try:
            conv = Conversation.objects.select_related('partnership', 'goal').get(id=instance.id)
            if conv.partnership_id:
                ConversationMembership.objects.get_or_create(conversation=conv, user_id=conv.partnership.user_a_id)
                ConversationMembership.objects.get_or_create(conversation=conv, user_id=conv.partnership.user_b_id)
            elif conv.goal_id:
                for uid in conv.goal.members.values_list('id', flat=True):
                    ConversationMembership.objects.get_or_create(conversation=conv, user_id=uid)
            _broadcast_conversation_state(conv.id)
        except Exception:
            logger.exception('Failed to broadcast new conversation websocket update')

    transaction.on_commit(_send_after_commit)


@receiver(post_save, sender=ConversationMembership)
def broadcast_conversation_membership_created(sender, instance: ConversationMembership, created: bool, **kwargs):
    if not created:
        return
    transaction.on_commit(lambda: _broadcast_conversation_state(instance.conversation_id))


def _email_notifications_enabled() -> bool:
    enabled = bool(getattr(settings, 'EMAIL_NOTIFICATIONS_ENABLED', False))
    if not enabled:
        return False
    # Require Mailgun config as well, otherwise skip silently.
    return bool(
        getattr(settings, 'MAILGUN_API_KEY', '')
        and getattr(settings, 'MAILGUN_DOMAIN', '')
        and getattr(settings, 'MAILGUN_FROM_EMAIL', '')
    )


def _notification_email_content(notification: Notification) -> tuple[str, str]:
    ntype = (notification.type or '').strip()
    payload = notification.payload or {}

    if ntype == 'new_match':
        subject = 'You have a new match'
        text = 'You have a new match on Padlupp. Open the app to view details.'
        return subject, text

    if ntype == 'new_task':
        title = payload.get('title') or 'a new task'
        subject = 'New task from your partner'
        text = f"Your partner created a new task: {title}. Open the app to view it."
        return subject, text

    if ntype == 'review_requested':
        title = payload.get('title') or 'a task'
        subject = 'Review requested'
        text = f"Your partner requested a review for: {title}. Open the app to review it."
        return subject, text

    if ntype == 'evidence_submitted':
        subject = 'Evidence submitted'
        text = 'Your partner submitted evidence for a task. Open the app to review it.'
        return subject, text

    if ntype == 'task_approved':
        subject = 'Task approved'
        text = 'Your task was approved by your partner. Open the app to see the update.'
        return subject, text

    if ntype == 'task_changes_requested':
        subject = 'Changes requested'
        comment = payload.get('comment')
        if comment:
            text = f"Your partner requested changes on a task. Comment: {comment}"
        else:
            text = 'Your partner requested changes on a task. Open the app to see details.'
        return subject, text

    if ntype == 'buddy_request_accepted':
        subject = 'Connection request accepted'
        text = 'Your connection request was accepted. Open the app to connect with them now.'
        return subject, text

    subject = 'New notification'
    text = f"You have a new notification ({ntype or 'unknown'}). Open the app to view it."
    return subject, text


@receiver(post_save, sender=Notification)
def email_notification_created(sender, instance: Notification, created: bool, **kwargs):
    if not created:
        return
    if not _email_notifications_enabled():
        return

    user = getattr(instance, 'user', None)
    if not user:
        return
    to_email = getattr(user, 'preferred_notification_email', None) or getattr(user, 'email', None)
    if not to_email:
        return

    subject, text = _notification_email_content(instance)

    def _send_after_commit():
        try:
            send_mailgun_email(
                to_email=to_email,
                subject=subject,
                text=text,
                tags=['notification', instance.type or 'unknown'],
            )
        except EmailSendError:
            logger.exception('Failed to send notification email')
        except Exception:
            logger.exception('Unexpected error sending notification email')

    transaction.on_commit(_send_after_commit)
