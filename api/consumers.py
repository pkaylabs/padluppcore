import json

from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.contrib.auth.models import AnonymousUser
from knox.auth import TokenAuthentication

from accounts.models import User
from .models import Conversation, Message
from .serializers import MessageSerializer


class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.conversation_id = self.scope['url_route']['kwargs']['conversation_id']
        self.group_name = f'chat_{self.conversation_id}'

        # Authenticate via knox token passed as query param ?token=...
        user = await self.authenticate_user()
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

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive(self, text_data=None, bytes_data=None):
        if not text_data:
            return

        data = json.loads(text_data)
        text = data.get('text')
        if not text:
            return

        user = self.scope['user']
        message = await self.create_message(user.id, self.conversation_id, text)
        serialized = MessageSerializer(message).data

        await self.channel_layer.group_send(
            self.group_name,
            {
                'type': 'chat.message',
                'message': serialized,
            },
        )

    async def chat_message(self, event):
        await self.send(text_data=json.dumps(event['message']))

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
    def get_user_from_token(self, token):
        auth = TokenAuthentication()
        try:
            user_auth_tuple = auth.authenticate_credentials(token.encode())
        except Exception:
            return None
        return user_auth_tuple[0] if user_auth_tuple else None

    async def authenticate_user(self):
        query_string = self.scope.get('query_string', b'').decode()
        params = dict(item.split('=') for item in query_string.split('&') if '=' in item)
        token = params.get('token')
        if not token:
            return None
        user = await self.get_user_from_token(token)
        if user and user.is_authenticated:
            self.scope['user'] = user
            return user
        return None
