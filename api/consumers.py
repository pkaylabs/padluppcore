import json
from urllib.parse import parse_qs

from django.conf import settings

from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.core.cache import cache
from django.utils import timezone
from knox.auth import TokenAuthentication

from accounts.models import User
from .models import Conversation, Message
from .serializers import MessageSerializer


class _ScopeRequest:
    """Minimal request-like object for DRF serializers in websockets.

    Provides build_absolute_uri() using ASGI scope (scheme + Host header).
    """

    def __init__(self, scope: dict):
        self._scope = scope or {}

    def build_absolute_uri(self, location: str) -> str:
        if not location:
            return location
        if isinstance(location, str) and (location.startswith('http://') or location.startswith('https://')):
            return location

        scheme = self._scope.get('scheme') or 'http'
        headers = {k.decode().lower(): v.decode() for k, v in (self._scope.get('headers') or [])}
        host = headers.get('host')
        if not host:
            server = self._scope.get('server')
            if server and isinstance(server, (list, tuple)) and len(server) >= 2:
                host, port = server[0], server[1]
                if port and ((scheme == 'http' and int(port) != 80) or (scheme == 'https' and int(port) != 443)):
                    host = f"{host}:{port}"
                else:
                    host = str(host)

        # Fallback for cases where scope doesn't have host info.
        if not host:
            base = getattr(settings, 'PUBLIC_BASE_URL', '') or getattr(settings, 'SITE_URL', '')
            if base:
                return base.rstrip('/') + '/' + location.lstrip('/')
            return location

        return f"{scheme}://{host}".rstrip('/') + '/' + location.lstrip('/')


class ConversationsConsumer(AsyncWebsocketConsumer):
    """Per-user conversations list websocket.

    Connect at: ws/conversations/?token=...

    - Sends initial list: {"type": "conversations", "conversations": [...]}
    - Receives group updates from server and forwards them:
      {"type": "conversation_update", "conversation": {...}}
    """

    async def connect(self):
        user = await self.authenticate_user()
        if not user:
            await self.close()
            return
        self.user = user
        self.serializer_request = _ScopeRequest(self.scope)
        self.group_name = f'conversations_user_{user.id}'
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

        conversations = await self.get_user_conversations_payload(user.id)
        await self.send_json({'type': 'conversations', 'conversations': conversations})

    async def disconnect(self, close_code):
        group_name = getattr(self, 'group_name', None)
        if group_name:
            await self.channel_layer.group_discard(group_name, self.channel_name)

    async def receive(self, text_data=None, bytes_data=None):
        # Currently read-only from client. (Client updates happen via chat socket.)
        return

    async def conversations_update(self, event):
        payload = event.get('payload')
        if not payload:
            return
        await self.send_json({'type': 'conversation_update', 'conversation': payload})

    async def send_json(self, payload: dict):
        await self.send(text_data=json.dumps(payload))

    @database_sync_to_async
    def get_user_conversations_payload(self, user_id: int):
        # Import locally to avoid circular imports at module load.
        from django.db.models import Q
		
        convs = list(
            Conversation.objects.select_related('partnership')
            .filter(Q(partnership__user_a_id=user_id) | Q(partnership__user_b_id=user_id))
            .order_by('-created_at')
        )
        conv_ids = [c.id for c in convs]
        if not conv_ids:
            return []

        # Fetch last message per conversation (best-effort, avoids N+1).
        last_msg_id_by_conv = {}
        for conv_id, msg_id in (
            Message.objects.filter(conversation_id__in=conv_ids)
            .order_by('conversation_id', '-created_at')
            .values_list('conversation_id', 'id')
        ):
            if conv_id not in last_msg_id_by_conv:
                last_msg_id_by_conv[conv_id] = msg_id

        last_msgs = Message.objects.select_related('sender').in_bulk(last_msg_id_by_conv.values())

        result = []
        for conv in convs:
            last_msg = last_msgs.get(last_msg_id_by_conv.get(conv.id))
            unread_count = (
                Message.objects.filter(conversation_id=conv.id, is_read=False)
                .exclude(sender_id=user_id)
                .count()
            )
            result.append(
                {
                    'id': conv.id,
                    'partnership': conv.partnership_id,
                    'last_message': MessageSerializer(last_msg, context={'request': self.serializer_request}).data if last_msg else None,
                    'unread_count': unread_count,
                    'created_at': conv.created_at.isoformat() if conv.created_at else None,
                    'updated_at': conv.updated_at.isoformat() if conv.updated_at else None,
                }
            )
        return result

    @database_sync_to_async
    def get_user_from_token(self, token):
        auth = TokenAuthentication()
        try:
            user_auth_tuple = auth.authenticate_credentials(token.encode())
        except Exception:
            return None
        return user_auth_tuple[0] if user_auth_tuple else None

    async def authenticate_user(self):
        query_string = self.scope.get('query_string', b'').decode()
        params = parse_qs(query_string)
        token = (params.get('token') or [None])[0]
        if not token:
            return None
        user = await self.get_user_from_token(token)
        if user and user.is_authenticated:
            self.scope['user'] = user
            return user
        return None


class ChatConsumer(AsyncWebsocketConsumer):
    HISTORY_LIMIT = 50
    PRESENCE_TTL_SECONDS = 60

    async def connect(self):
        self.conversation_id = self.scope['url_route']['kwargs']['conversation_id']
        self.group_name = f'chat_{self.conversation_id}'

        # Authenticate via knox token passed as query param ?token=...
        user = await self.authenticate_user()
        self.serializer_request = _ScopeRequest(self.scope)
        if not user:
            await self.close()
            return

        # Verify user is part of the conversation
        is_allowed = await self.user_in_conversation(user.id, self.conversation_id)
        if not is_allowed:
            await self.close()
            return

        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

        # Presence tracking (best-effort)
        await self.set_user_online(user.id, self.conversation_id, True)
        await self.broadcast_presence()

        # Send message history to the connecting client
        history = await self.get_message_history(self.conversation_id, limit=self.HISTORY_LIMIT)
        await self.send_json({'type': 'history', 'messages': history})

        # Send a presence snapshot to the connecting client
        online_ids = await self.get_online_user_ids(self.conversation_id)
        await self.send_json({'type': 'presence', 'online_user_ids': online_ids})

        # Also push a conversations-list update for this conversation.
        await self.broadcast_conversation_updates()

    async def disconnect(self, close_code):
        user = self.scope.get('user')
        if user and getattr(user, 'is_authenticated', False):
            await self.set_user_online(user.id, self.conversation_id, False)
            await self.broadcast_presence()
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive(self, text_data=None, bytes_data=None):
        if not text_data:
            return

        try:
            data = json.loads(text_data)
        except json.JSONDecodeError:
            return

        msg_type = data.get('type') or 'message'

        user = self.scope.get('user')
        if not user or not getattr(user, 'is_authenticated', False):
            return

        # Default: create a message from text.
        if msg_type == 'message':
            text = (data.get('text') or '').strip()
            if not text:
                return

            message = await self.create_message(user.id, self.conversation_id, text)
            serialized = MessageSerializer(message, context={'request': self.serializer_request}).data

            # Delivery ack to the sender (message persisted)
            await self.send_json({'type': 'ack', 'ack': 'received', 'message_id': message.id})

            await self.channel_layer.group_send(
                self.group_name,
                {
                    'type': 'chat.message',
                    'message': serialized,
                },
            )
            await self.broadcast_conversation_updates()
            return

        # Typing indicator
        if msg_type == 'typing':
            await self.channel_layer.group_send(
                self.group_name,
                {
                    'type': 'chat.typing',
                    'user_id': user.id,
                    'is_typing': bool(data.get('is_typing', True)),
                },
            )
            return

        # Delivery acknowledgement from client (no DB state stored)
        if msg_type == 'delivered':
            message_id = data.get('message_id')
            if not isinstance(message_id, int):
                return
            ok = await self.message_belongs_to_conversation(message_id, self.conversation_id)
            if not ok:
                return
            await self.channel_layer.group_send(
                self.group_name,
                {
                    'type': 'chat.delivered',
                    'message_id': message_id,
                    'by_user_id': user.id,
                },
            )
            return

        # Mark a list of messages as read (optional helper for unread counts)
        if msg_type == 'read':
            ids = data.get('message_ids') or []
            if not isinstance(ids, list) or not all(isinstance(x, int) for x in ids):
                return
            await self.mark_messages_read(user.id, self.conversation_id, ids)
            await self.channel_layer.group_send(
                self.group_name,
                {
                    'type': 'chat.read',
                    'message_ids': ids,
                    'by_user_id': user.id,
                },
            )
            await self.broadcast_conversation_updates()
            return

        # Mark all messages as read (optional helper)
        if msg_type == 'read_all':
            await self.mark_all_messages_read(user.id, self.conversation_id)
            await self.channel_layer.group_send(
                self.group_name,
                {
                    'type': 'chat.read_all',
                    'by_user_id': user.id,
                },
            )
            await self.broadcast_conversation_updates()
            return

    async def broadcast_conversation_updates(self):
        """Notify each participant's conversations websocket about this conversation."""
        participants = await self.get_conversation_participant_ids(self.conversation_id)
        if not participants:
            return
        for uid in participants:
            payload = await self.get_conversation_payload_for_user(self.conversation_id, uid)
            if not payload:
                continue
            await self.channel_layer.group_send(
                f'conversations_user_{uid}',
                {'type': 'conversations.update', 'payload': payload},
            )

    @database_sync_to_async
    def get_conversation_participant_ids(self, conversation_id: int):
        try:
            conv = Conversation.objects.select_related('partnership').get(id=conversation_id)
        except Conversation.DoesNotExist:
            return []
        return [conv.partnership.user_a_id, conv.partnership.user_b_id]

    @database_sync_to_async
    def get_conversation_payload_for_user(self, conversation_id: int, user_id: int):
        try:
            conv = Conversation.objects.select_related('partnership').get(id=conversation_id)
        except Conversation.DoesNotExist:
            return None
        last_msg = (
            Message.objects.select_related('sender')
            .filter(conversation_id=conversation_id)
            .order_by('-created_at')
            .first()
        )
        unread_count = (
            Message.objects.filter(conversation_id=conversation_id, is_read=False)
            .exclude(sender_id=user_id)
            .count()
        )
        return {
            'id': conv.id,
            'partnership': conv.partnership_id,
            'last_message': MessageSerializer(last_msg, context={'request': self.serializer_request}).data if last_msg else None,
            'unread_count': unread_count,
            'created_at': conv.created_at.isoformat() if conv.created_at else None,
            'updated_at': conv.updated_at.isoformat() if conv.updated_at else None,
        }

    async def chat_message(self, event):
        # Backward-compatible: message payload is sent as the serialized dict.
        await self.send(text_data=json.dumps(event['message']))

    async def chat_typing(self, event):
        await self.send_json({'type': 'typing', 'user_id': event['user_id'], 'is_typing': event['is_typing']})

    async def chat_presence(self, event):
        await self.send_json({'type': 'presence', 'online_user_ids': event['online_user_ids']})

    async def chat_delivered(self, event):
        await self.send_json({'type': 'delivered', 'message_id': event['message_id'], 'by_user_id': event['by_user_id']})

    async def chat_read(self, event):
        await self.send_json({'type': 'read', 'message_ids': event['message_ids'], 'by_user_id': event['by_user_id']})

    async def chat_read_all(self, event):
        await self.send_json({'type': 'read_all', 'by_user_id': event['by_user_id']})

    async def send_json(self, payload: dict):
        await self.send(text_data=json.dumps(payload))

    async def broadcast_presence(self):
        online_ids = await self.get_online_user_ids(self.conversation_id)
        await self.channel_layer.group_send(
            self.group_name,
            {'type': 'chat.presence', 'online_user_ids': online_ids},
        )

    def _presence_cache_key(self, conversation_id: int) -> str:
        return f'chat:conversation:{conversation_id}:online_user_ids'

    @database_sync_to_async
    def get_online_user_ids(self, conversation_id: int):
        key = self._presence_cache_key(conversation_id)
        ids = cache.get(key) or []
        return sorted({int(x) for x in ids})

    @database_sync_to_async
    def set_user_online(self, user_id: int, conversation_id: int, online: bool):
        key = self._presence_cache_key(conversation_id)
        current = cache.get(key) or []
        s = {int(x) for x in current}
        if online:
            s.add(int(user_id))
        else:
            s.discard(int(user_id))
        cache.set(key, list(s), timeout=self.PRESENCE_TTL_SECONDS)

    @database_sync_to_async
    def user_in_conversation(self, user_id, conversation_id):
        try:
            conv = Conversation.objects.select_related('partnership__user_a', 'partnership__user_b').get(id=conversation_id)
        except Conversation.DoesNotExist:
            return False
        return user_id in [conv.partnership.user_a_id, conv.partnership.user_b_id]

    @database_sync_to_async
    def create_message(self, user_id, conversation_id, text):
        user = User.objects.get(id=user_id)
        conversation = Conversation.objects.get(id=conversation_id)
        return Message.objects.create(conversation=conversation, sender=user, text=text)

    @database_sync_to_async
    def get_message_history(self, conversation_id, limit: int = 50):
        qs = (
            Message.objects.select_related('sender')
            .filter(conversation_id=conversation_id)
            .order_by('-created_at')[:limit]
        )
        items = list(qs)[::-1]
        return MessageSerializer(items, many=True, context={'request': self.serializer_request}).data

    @database_sync_to_async
    def message_belongs_to_conversation(self, message_id: int, conversation_id) -> bool:
        return Message.objects.filter(id=message_id, conversation_id=conversation_id).exists()

    @database_sync_to_async
    def mark_messages_read(self, user_id: int, conversation_id, message_ids: list[int]):
        return (
            Message.objects.filter(conversation_id=conversation_id, id__in=message_ids)
            .exclude(sender_id=user_id)
            .update(is_read=True, updated_at=timezone.now())
        )

    @database_sync_to_async
    def mark_all_messages_read(self, user_id: int, conversation_id):
        return (
            Message.objects.filter(conversation_id=conversation_id, is_read=False)
            .exclude(sender_id=user_id)
            .update(is_read=True, updated_at=timezone.now())
        )

    @database_sync_to_async
    def get_user_from_token(self, token):
        auth = TokenAuthentication()
        try:
            user_auth_tuple = auth.authenticate_credentials(token.encode())
        except Exception:
            return None
        return user_auth_tuple[0] if user_auth_tuple else None

    async def authenticate_user(self):
        query_string = self.scope.get('query_string', b'').decode()
        params = parse_qs(query_string)
        token = (params.get('token') or [None])[0]
        if not token:
            return None
        user = await self.get_user_from_token(token)
        if user and user.is_authenticated:
            self.scope['user'] = user
            return user
        return None
