import asyncio
import base64
import binascii
import json
from datetime import timedelta
from urllib.parse import parse_qs

from django.conf import settings
from django.core.files.base import ContentFile
from django.db.models.functions import Coalesce
from django.utils.text import get_valid_filename

from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.core.cache import cache
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from knox.auth import TokenAuthentication

from accounts.models import User
from .models import Conversation, Message
from .serializers import MessageSerializer, UserSerializer


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
        try:
            await self.send(text_data=json.dumps(payload))
        except Exception:
            pass

    @database_sync_to_async
    def get_user_conversations_payload(self, user_id: int):
        # Import locally to avoid circular imports at module load.
        from django.db.models import Q
		
        convs = list(
            Conversation.objects.select_related('partnership', 'partnership__user_a', 'partnership__user_b', 'goal')
            .prefetch_related('members')
            .filter(Q(members__id=user_id) | Q(partnership__user_a_id=user_id) | Q(partnership__user_b_id=user_id) | Q(goal__members__id=user_id))
            .distinct()
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
            member_users = list(conv.members.all()) if conv.members.exists() else []
            if conv.is_group and conv.goal_id:
                partner_data = {'name': conv.goal.title, 'avatar': None}
            elif conv.partnership_id:
                partner_user = conv.partnership.user_b if conv.partnership.user_a_id == user_id else conv.partnership.user_a
                partner_data = UserSerializer(partner_user, context={'request': self.serializer_request}).data if partner_user else {}
            elif member_users:
                partner_data = {'name': ', '.join([u.name for u in member_users]), 'avatar': None}
            else:
                partner_data = {}
            member_ids = list(conv.members.values_list('id', flat=True))
            if not member_ids:
                if conv.partnership_id:
                    member_ids = [conv.partnership.user_a_id, conv.partnership.user_b_id]
                elif conv.goal_id:
                    member_ids = list(conv.goal.members.values_list('id', flat=True))
            unread_count = (
                Message.objects.filter(conversation_id=conv.id, is_read=False)
                .exclude(sender_id=user_id)
                .count()
            )
            result.append(
                {
                    'id': conv.id,
                    'partnership': conv.partnership_id,
                    'goal': conv.goal_id,
                    'is_group': conv.is_group,
                    'partner_name': conv.name or partner_data.get('name'),
                    'partner_avatar': partner_data.get('avatar'),
                    'display_name': conv.name or partner_data.get('name'),
                    'name': conv.name,
                    'member_ids': member_ids,
                    'member_names': [u.name for u in member_users],
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
    PRESENCE_HEARTBEAT_SECONDS = 30
    PRESENCE_STALE_SECONDS = 90
    DEFAULT_MAX_UPLOAD_BYTES = 25 * 1024 * 1024  # 25MB

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

        # Pending metadata for a binary-frame upload (set by client via {"type":"file_meta",...}).
        self._pending_file_meta = None

        # Presence tracking (best-effort)
        await self.set_user_online(user.id, self.conversation_id, True, self.channel_name)
        self._presence_heartbeat_task = asyncio.create_task(self._presence_heartbeat())
        await self.broadcast_presence()

        # Send message history to the connecting client
        history = await self.get_message_history(self.conversation_id, limit=self.HISTORY_LIMIT)
        await self.send_json({'type': 'history', 'messages': history})

        # Send a presence snapshot to the connecting client
        online_ids = await self.get_online_user_ids(self.conversation_id)
        last_seen_at_by_user_id = await self.get_last_seen_at_by_user_id(self.conversation_id)
        participants = await self.get_conversation_participant_ids(self.conversation_id)
        if participants:
            online_ids = sorted(set(online_ids) & set(participants))
            last_seen_at_by_user_id = {str(uid): last_seen_at_by_user_id.get(str(uid)) for uid in participants if str(uid) in last_seen_at_by_user_id}
        await self.send_json({'type': 'presence', 'online_user_ids': online_ids, 'last_seen_at_by_user_id': last_seen_at_by_user_id})

        # Also push a conversations-list update for this conversation.
        await self.broadcast_conversation_updates()

    async def disconnect(self, close_code):
        heartbeat_task = getattr(self, '_presence_heartbeat_task', None)
        if heartbeat_task:
            heartbeat_task.cancel()

        user = self.scope.get('user')
        if (
            user
            and getattr(user, 'is_authenticated', False)
            and getattr(self, 'conversation_id', None)
        ):
            await self.set_user_online(user.id, self.conversation_id, False, self.channel_name)
            await self.broadcast_presence()
        group_name = getattr(self, 'group_name', None)
        if group_name:
            await self.channel_layer.group_discard(group_name, self.channel_name)

    async def _presence_heartbeat(self):
        try:
            while True:
                await asyncio.sleep(self.PRESENCE_HEARTBEAT_SECONDS)
                user = self.scope.get('user')
                if not user or not getattr(user, 'is_authenticated', False):
                    return
                await self.set_user_online(
                    user.id,
                    self.conversation_id,
                    True,
                    self.channel_name,
                )
        except asyncio.CancelledError:
            return

    def _max_upload_bytes(self) -> int:
        try:
            v = int(getattr(settings, 'CHAT_UPLOAD_MAX_BYTES', self.DEFAULT_MAX_UPLOAD_BYTES))
            return v if v > 0 else self.DEFAULT_MAX_UPLOAD_BYTES
        except Exception:
            return self.DEFAULT_MAX_UPLOAD_BYTES

    def _is_allowed_upload_mime(self, mime: str) -> bool:
        mime = (mime or '').strip().lower()
        return mime.startswith('image/') or mime.startswith('video/')

    def _sanitize_filename(self, filename: str, fallback: str = 'upload.bin') -> str:
        name = (filename or '').strip()
        if not name:
            return fallback
        # Prevent path traversal and keep it reasonably clean.
        name = name.replace('\\', '/').split('/')[-1]
        name = get_valid_filename(name)
        return name or fallback

    async def receive(self, text_data=None, bytes_data=None):
        user = self.scope.get('user')
        if not user or not getattr(user, 'is_authenticated', False):
            return

        # Binary frame upload (requires prior file_meta message).
        if bytes_data is not None:
            meta = getattr(self, '_pending_file_meta', None)
            if not meta:
                return
            self._pending_file_meta = None

            max_bytes = self._max_upload_bytes()
            if len(bytes_data) > max_bytes:
                await self.send_json({'type': 'error', 'error': 'file_too_large', 'max_bytes': max_bytes})
                return

            filename = self._sanitize_filename(meta.get('filename'), fallback='upload.bin')
            content_type = (meta.get('content_type') or '').strip().lower()
            caption = (meta.get('text') or '').strip()
            if not self._is_allowed_upload_mime(content_type):
                await self.send_json({'type': 'error', 'error': 'unsupported_content_type'})
                return

            content = ContentFile(bytes_data, name=filename)
            try:
                message = await self.create_message(
                    user.id,
                    self.conversation_id,
                    caption,
                    attachment=content,
                    attachment_name=filename,
                    attachment_mime=content_type,
                    attachment_size=len(bytes_data),
                    reply_to_message_id=meta.get('reply_to_message_id'),
                )
            except ValueError:
                await self.send_json({'type': 'error', 'error': 'invalid_reply_target'})
                return
            serialized = MessageSerializer(message, context={'request': self.serializer_request}).data

            await self.send_json({'type': 'ack', 'ack': 'received', 'message_id': message.id})
            await self.channel_layer.group_send(self.group_name, {'type': 'chat.message', 'message': serialized})
            await self.broadcast_conversation_updates()
            return

        if not text_data:
            return

        try:
            data = json.loads(text_data)
        except json.JSONDecodeError:
            return

        msg_type = data.get('type') or 'message'

        # Default: create a message from text.
        if msg_type == 'message':
            text = (data.get('text') or '').strip()
            if not text:
                return

            try:
                message = await self.create_message(
                    user.id,
                    self.conversation_id,
                    text,
                    reply_to_message_id=data.get('reply_to_message_id'),
                )
            except ValueError:
                await self.send_json({'type': 'error', 'error': 'invalid_reply_target'})
                return
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

        # File upload via base64 payload (images/videos).
        # Client -> Server:
        # {"type":"file","filename":"pic.jpg","content_type":"image/jpeg","data":"<base64>","text":"optional caption"}
        if msg_type == 'file':
            b64 = (data.get('data') or '').strip()
            filename = self._sanitize_filename(data.get('filename'), fallback='upload.bin')
            content_type = (data.get('content_type') or '').strip().lower()
            caption = (data.get('text') or '').strip()
            reply_to_message_id = data.get('reply_to_message_id')
            if not b64 or not content_type:
                await self.send_json({'type': 'error', 'error': 'missing_fields'})
                return
            if not self._is_allowed_upload_mime(content_type):
                await self.send_json({'type': 'error', 'error': 'unsupported_content_type'})
                return

            try:
                raw = base64.b64decode(b64, validate=True)
            except (binascii.Error, ValueError):
                await self.send_json({'type': 'error', 'error': 'invalid_base64'})
                return

            max_bytes = self._max_upload_bytes()
            if len(raw) > max_bytes:
                await self.send_json({'type': 'error', 'error': 'file_too_large', 'max_bytes': max_bytes})
                return

            content = ContentFile(raw, name=filename)
            try:
                message = await self.create_message(
                    user.id,
                    self.conversation_id,
                    caption,
                    attachment=content,
                    attachment_name=filename,
                    attachment_mime=content_type,
                    attachment_size=len(raw),
                    reply_to_message_id=reply_to_message_id,
                )
            except ValueError:
                await self.send_json({'type': 'error', 'error': 'invalid_reply_target'})
                return
            serialized = MessageSerializer(message, context={'request': self.serializer_request}).data

            await self.send_json({'type': 'ack', 'ack': 'received', 'message_id': message.id})
            await self.channel_layer.group_send(self.group_name, {'type': 'chat.message', 'message': serialized})
            await self.broadcast_conversation_updates()
            return

        # Two-step binary upload:
        # 1) client sends metadata:
        #    {"type":"file_meta","filename":"clip.mp4","content_type":"video/mp4","text":"optional"}
        # 2) client sends a single binary websocket frame with the file bytes.
        if msg_type == 'file_meta':
            filename = self._sanitize_filename(data.get('filename'), fallback='upload.bin')
            content_type = (data.get('content_type') or '').strip().lower()
            caption = (data.get('text') or '').strip()
            reply_to_message_id = data.get('reply_to_message_id')
            if not content_type or not filename:
                await self.send_json({'type': 'error', 'error': 'missing_fields'})
                return
            if not self._is_allowed_upload_mime(content_type):
                await self.send_json({'type': 'error', 'error': 'unsupported_content_type'})
                return
            self._pending_file_meta = {'filename': filename, 'content_type': content_type, 'text': caption, 'reply_to_message_id': reply_to_message_id}
            await self.send_json({'type': 'ack', 'ack': 'ready_for_binary'})
            return

        # Typing indicator
        if msg_type == 'typing':
            await self.channel_layer.group_send(
                self.group_name,
                {
                    'type': 'chat.typing',
                    'user_id': user.id,
                    'user_name': getattr(user, 'name', None),
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
            conv = Conversation.objects.select_related('partnership', 'goal').prefetch_related('members').get(id=conversation_id)
        except Conversation.DoesNotExist:
            return []
        member_ids = list(conv.members.values_list('id', flat=True))
        if member_ids:
            return member_ids
        if conv.partnership_id:
            return [conv.partnership.user_a_id, conv.partnership.user_b_id]
        if conv.goal_id:
            return list(conv.goal.members.values_list('id', flat=True))
        return []

    @database_sync_to_async
    def get_conversation_payload_for_user(self, conversation_id: int, user_id: int):
        try:
            conv = Conversation.objects.select_related('partnership', 'partnership__user_a', 'partnership__user_b', 'goal').prefetch_related('members').get(id=conversation_id)
        except Conversation.DoesNotExist:
            return None
        member_users = list(conv.members.all()) if conv.members.exists() else []
        if conv.is_group and conv.goal_id:
            partner_data = {'name': conv.goal.title, 'avatar': None}
        elif conv.partnership_id:
            partner_user = conv.partnership.user_b if conv.partnership.user_a_id == user_id else conv.partnership.user_a
            partner_data = UserSerializer(partner_user, context={'request': self.serializer_request}).data if partner_user else {}
        elif member_users:
            partner_data = {'name': ', '.join([u.name for u in member_users]), 'avatar': None}
        else:
            partner_data = {}
        member_ids = list(conv.members.values_list('id', flat=True))
        if not member_ids:
            if conv.partnership_id:
                member_ids = [conv.partnership.user_a_id, conv.partnership.user_b_id]
            elif conv.goal_id:
                member_ids = list(conv.goal.members.values_list('id', flat=True))
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
            'goal': conv.goal_id,
            'is_group': conv.is_group,
            'partner_name': partner_data.get('name'),
            'partner_avatar': partner_data.get('avatar'),
            'display_name': partner_data.get('name'),
            'member_ids': member_ids,
            'member_names': [u.name for u in member_users],
            'last_message': MessageSerializer(last_msg, context={'request': self.serializer_request}).data if last_msg else None,
            'unread_count': unread_count,
            'created_at': conv.created_at.isoformat() if conv.created_at else None,
            'updated_at': conv.updated_at.isoformat() if conv.updated_at else None,
        }

    async def chat_message(self, event):
        # Backward-compatible: message payload is sent as the serialized dict.
        await self.send(text_data=json.dumps(event['message']))

    async def chat_typing(self, event):
        try:
            await self.send_json(
                {
                    'type': 'typing',
                    'user_id': event['user_id'],
                    'user_name': event.get('user_name'),
                    'is_typing': event['is_typing'],
                }
            )
        except Exception:
            pass

    async def chat_presence(self, event):
        try:
            await self.send_json({'type': 'presence', 'online_user_ids': event['online_user_ids'], 'online_user_count': event['online_user_count'], 'last_seen_at_by_user_id': event.get('last_seen_at_by_user_id', {})})
        except Exception:
            pass

    async def chat_delivered(self, event):
        try:
            await self.send_json({'type': 'delivered', 'message_id': event['message_id'], 'by_user_id': event['by_user_id']})
        except Exception:
            pass

    async def chat_read(self, event):
        try:
            await self.send_json({'type': 'read', 'message_ids': event['message_ids'], 'by_user_id': event['by_user_id']})
        except Exception:
            pass

    async def chat_read_all(self, event):
        try:
            await self.send_json({'type': 'read_all', 'by_user_id': event['by_user_id']})
        except Exception:
            pass

    async def send_json(self, payload: dict):
        await self.send(text_data=json.dumps(payload))

    async def broadcast_presence(self):
        online_ids = await self.get_online_user_ids(self.conversation_id)
        last_seen_at_by_user_id = await self.get_last_seen_at_by_user_id(self.conversation_id)
        participants = await self.get_conversation_participant_ids(self.conversation_id)
        if participants:
            online_ids = sorted(set(online_ids) & set(participants))
            last_seen_at_by_user_id = {str(uid): last_seen_at_by_user_id.get(str(uid)) for uid in participants if str(uid) in last_seen_at_by_user_id}
        await self.channel_layer.group_send(
            self.group_name,
            {'type': 'chat.presence', 'online_user_ids': online_ids, 'online_user_count': len(online_ids), 'last_seen_at_by_user_id': last_seen_at_by_user_id},
        )

    def _presence_cache_key(self, conversation_id: int) -> str:
        return f'chat:conversation:{conversation_id}:online_user_ids'

    def _prune_presence_connections(self, connections: dict, now):
        cutoff = now - timedelta(seconds=self.PRESENCE_STALE_SECONDS)
        active = {}
        stale_last_seen = {}

        for user_id, raw_connections in connections.items():
            if not isinstance(raw_connections, dict):
                continue

            active_connections = {}
            latest_stale_at = None
            for connection_id, heartbeat_at_raw in raw_connections.items():
                heartbeat_at = parse_datetime(str(heartbeat_at_raw))
                if not heartbeat_at:
                    continue
                if timezone.is_naive(heartbeat_at):
                    heartbeat_at = timezone.make_aware(heartbeat_at, timezone.get_default_timezone())
                if heartbeat_at >= cutoff:
                    active_connections[str(connection_id)] = heartbeat_at.isoformat()
                elif latest_stale_at is None or heartbeat_at > latest_stale_at:
                    latest_stale_at = heartbeat_at

            if active_connections:
                active[str(user_id)] = active_connections
            elif latest_stale_at:
                stale_last_seen[int(user_id)] = latest_stale_at

        for user_id, last_seen_at in stale_last_seen.items():
            User.objects.filter(id=user_id).update(last_seen_at=last_seen_at)

        return active

    @database_sync_to_async
    def get_online_user_ids(self, conversation_id: int):
        key = self._presence_cache_key(conversation_id)
        connections = cache.get(key) or {}
        if not isinstance(connections, dict):
            return []
        connections = self._prune_presence_connections(connections, timezone.now())
        if connections:
            cache.set(key, connections, timeout=self.PRESENCE_STALE_SECONDS)
        else:
            cache.delete(key)
        return sorted(int(user_id) for user_id in connections)

    @database_sync_to_async
    def get_last_seen_at_by_user_id(self, conversation_id: int):
        try:
            conv = Conversation.objects.select_related('partnership', 'goal').prefetch_related('members').get(id=conversation_id)
        except Conversation.DoesNotExist:
            return {}

        participant_ids = list(conv.members.values_list('id', flat=True))
        if not participant_ids and conv.partnership_id:
            participant_ids = [conv.partnership.user_a_id, conv.partnership.user_b_id]
        elif not participant_ids and conv.goal_id:
            participant_ids = list(conv.goal.members.values_list('id', flat=True))

        return {
            str(user_id): effective_last_seen.isoformat()
            for user_id, effective_last_seen in User.objects.filter(
                id__in=participant_ids,
            )
            .annotate(
                effective_last_seen=Coalesce('last_seen_at', 'last_login', 'created_at')
            )
            .values_list('id', 'effective_last_seen')
        }

    @database_sync_to_async
    def set_user_online(self, user_id: int, conversation_id: int, online: bool, connection_id: str):
        key = self._presence_cache_key(conversation_id)
        connections = cache.get(key) or {}
        if not isinstance(connections, dict):
            connections = {}

        now = timezone.now()
        connections = self._prune_presence_connections(connections, now)
        user_key = str(user_id)
        user_connections = dict(connections.get(user_key) or {})
        if online:
            user_connections[connection_id] = now.isoformat()
            connections[user_key] = user_connections
        else:
            user_connections.pop(connection_id, None)
            if user_connections:
                connections[user_key] = user_connections
            else:
                connections.pop(user_key, None)
                User.objects.filter(id=user_id).update(last_seen_at=now)

        if connections:
            cache.set(key, connections, timeout=self.PRESENCE_STALE_SECONDS)
        else:
            cache.delete(key)

    @database_sync_to_async
    def user_in_conversation(self, user_id, conversation_id):
        try:
            conv = Conversation.objects.select_related('partnership__user_a', 'partnership__user_b', 'goal').prefetch_related('members').get(id=conversation_id)
        except Conversation.DoesNotExist:
            return False
        if conv.members.filter(id=user_id).exists():
            return True
        if conv.partnership_id and user_id in [conv.partnership.user_a_id, conv.partnership.user_b_id]:
            return True
        if conv.goal_id and conv.goal.members.filter(id=user_id).exists():
            return True
        return False

    @database_sync_to_async
    def create_message(
        self,
        user_id,
        conversation_id,
        text,
        *,
        attachment=None,
        attachment_name: str = '',
        attachment_mime: str = '',
        attachment_size: int | None = None,
        reply_to_message_id: int | None = None,
    ):
        user = User.objects.get(id=user_id)
        conversation = Conversation.objects.get(id=conversation_id)
        reply_to_message = None
        if reply_to_message_id:
            reply_to_message = Message.objects.filter(id=reply_to_message_id, conversation_id=conversation_id).first()
            if not reply_to_message:
                raise ValueError('Reply target must belong to the same conversation.')
        return Message.objects.create(
            conversation=conversation,
            sender=user,
            text=text or '',
            reply_to_message=reply_to_message,
            is_a_reply=bool(reply_to_message),
            attachment=attachment,
            attachment_name=attachment_name or '',
            attachment_mime=attachment_mime or '',
            attachment_size=attachment_size,
        )

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
