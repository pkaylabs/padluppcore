from __future__ import annotations

import logging

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.db import transaction
from django.db.models.signals import post_save
from django.dispatch import receiver

from .models import Conversation, Message
from .serializers import MessageSerializer

logger = logging.getLogger(__name__)


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
