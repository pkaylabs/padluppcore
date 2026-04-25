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
from .models import Conversation, Evidence, Goal, Message, Notification, Task, TimerSession
from .serializers import MessageSerializer

logger = logging.getLogger(__name__)


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

    partnership_id = getattr(instance, 'partnership_id', None)
    if not partnership_id:
        return

    def _send_after_commit():
        try:
            channel_layer = get_channel_layer()
            if not channel_layer:
                return

            # Fetch latest state and participants (avoid relying on cached relations).
            conv = Conversation.objects.select_related('partnership').get(id=instance.id)
            user_ids = [conv.partnership.user_a_id, conv.partnership.user_b_id]

            last_msg = (
                Message.objects.select_related('sender')
                .filter(conversation_id=conv.id)
                .order_by('-created_at')
                .first()
            )
            last_message_payload = MessageSerializer(last_msg, context={}).data if last_msg else None

            for uid in user_ids:
                unread_count = (
                    Message.objects.filter(conversation_id=conv.id, is_read=False)
                    .exclude(sender_id=uid)
                    .count()
                )
                payload = {
                    'id': conv.id,
                    'partnership': conv.partnership_id,
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
            # Best-effort only: never block DB writes/admin save on websocket issues.
            logger.exception('Failed to broadcast new conversation websocket update')

    transaction.on_commit(_send_after_commit)


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
