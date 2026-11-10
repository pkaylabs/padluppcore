"""Read receipts require a real recipient and exact, authorized message IDs."""

from datetime import timedelta

from asgiref.sync import async_to_sync
from channels.db import database_sync_to_async
from channels.routing import URLRouter
from channels.testing import WebsocketCommunicator
from django.test import TransactionTestCase, override_settings
from django.utils import timezone
from knox.models import AuthToken

from accounts.models import User
from .message_models import MessageHidden
from .models import Conversation, ConversationMembership, Message, Partnership
from .routing import websocket_urlpatterns
from .test_community_acceptance import CommunityFixtures, TEST_SETTINGS


@override_settings(**TEST_SETTINGS)
class MessageReadReceiptTests(CommunityFixtures, TransactionTestCase):
    def setUp(self):
        super().setUp()
        self.direct = Conversation.objects.create()
        for user in (self.owner, self.member):
            ConversationMembership.objects.create(conversation=self.direct, user=user)

    async def open_socket(self, user, conversation=None):
        conversation = conversation or self.direct
        _, token = await database_sync_to_async(AuthToken.objects.create)(user)
        socket = WebsocketCommunicator(
            URLRouter(websocket_urlpatterns), f'/ws/chat/{conversation.pk}/?token={token}',
        )
        connected, _ = await socket.connect()
        self.assertTrue(connected)
        history = False
        presences = 0
        for _ in range(10):
            event = await socket.receive_json_from(timeout=3)
            history |= event.get('type') == 'history'
            presences += event.get('type') == 'presence'
            if history and presences >= 2:
                break
        self.assertTrue(history)
        return socket

    async def receipt(self, socket):
        for _ in range(10):
            event = await socket.receive_json_from(timeout=3)
            if event.get('type') != 'presence':
                return event
        self.fail('No read receipt was delivered')

    def test_sender_read_all_does_not_ack_outgoing_while_buddy_is_offline(self):
        last_seen = timezone.now() - timedelta(days=4)
        User.objects.filter(pk=self.member.pk).update(last_seen_at=last_seen)
        outgoing = self.message(conversation=self.direct)
        incoming = Message.objects.create(conversation=self.direct, sender=self.member, text='Old reply')

        async def exercise():
            sender = await self.open_socket(self.owner)
            try:
                await sender.send_json_to({'type': 'message', 'text': 'Just sent while buddy is offline'})
                ack = await sender.receive_json_from(timeout=3)
                self.assertEqual(ack.get('type'), 'ack')
                sent = await sender.receive_json_from(timeout=3)
                self.assertEqual(sent['text'], 'Just sent while buddy is offline')
                self.assertFalse(sent['is_read'])
                await sender.send_json_to({'type': 'read_all'})
                self.assertTrue(await sender.receive_nothing(timeout=0.2))
                return sent['id']
            finally:
                await sender.disconnect()

        sent_id = async_to_sync(exercise)()
        outgoing.refresh_from_db()
        incoming.refresh_from_db()
        self.member.refresh_from_db()
        self.assertFalse(outgoing.is_read)
        self.assertFalse(Message.objects.get(pk=sent_id).is_read)
        self.assertTrue(incoming.is_read)
        self.assertEqual(self.member.last_seen_at, last_seen)

    def test_peer_read_all_contains_only_newly_read_incoming_ids(self):
        outgoing = self.message(conversation=self.direct)
        already_read = self.message(conversation=self.direct, is_read=True)
        incoming = Message.objects.create(conversation=self.direct, sender=self.member, text='Reply')
        unrelated = self.message(conversation=self.conversation)

        async def exercise():
            sender = await self.open_socket(self.owner)
            recipient = await self.open_socket(self.member)
            try:
                await recipient.send_json_to({'type': 'read_all'})
                self.assertEqual(await self.receipt(sender), {
                    'type': 'read_all', 'by_user_id': self.member.pk,
                    'conversation_id': self.direct.pk, 'message_ids': [outgoing.pk],
                })
                self.assertTrue(await recipient.receive_nothing(timeout=0.2))
                await recipient.send_json_to({'type': 'read_all'})
                self.assertTrue(await sender.receive_nothing(timeout=0.2))
            finally:
                await recipient.disconnect()
                await sender.disconnect()

        async_to_sync(exercise)()
        for message, read in ((outgoing, True), (already_read, True), (incoming, False), (unrelated, False)):
            message.refresh_from_db()
            self.assertEqual(message.is_read, read)
        newer = self.message(conversation=self.direct)
        self.assertFalse(newer.is_read)

    def test_read_list_does_not_echo_own_hidden_or_foreign_ids(self):
        outgoing = self.message(conversation=self.direct)
        own = Message.objects.create(conversation=self.direct, sender=self.member, text='Own')
        hidden = self.message(conversation=self.direct)
        MessageHidden.objects.create(message=hidden, user=self.member)
        foreign = self.message(conversation=self.conversation)
        ids = [outgoing.pk, outgoing.pk, own.pk, hidden.pk, foreign.pk, 999999]

        async def exercise():
            sender = await self.open_socket(self.owner)
            recipient = await self.open_socket(self.member)
            try:
                await recipient.send_json_to({'type': 'read', 'message_ids': ids})
                self.assertEqual(await self.receipt(sender), {
                    'type': 'read', 'by_user_id': self.member.pk,
                    'conversation_id': self.direct.pk, 'message_ids': [outgoing.pk],
                })
                self.assertTrue(await recipient.receive_nothing(timeout=0.2))
            finally:
                await recipient.disconnect()
                await sender.disconnect()

        async_to_sync(exercise)()
        outgoing.refresh_from_db()
        self.assertTrue(outgoing.is_read)
        for message in (own, hidden, foreign):
            message.refresh_from_db()
            self.assertFalse(message.is_read)

    def test_empty_invalid_and_own_message_receipts_are_ignored(self):
        own = self.message(conversation=self.direct)

        async def exercise():
            sender = await self.open_socket(self.owner)
            try:
                for ids in ([], [own.pk], [True], [-1], [str(own.pk)], 'all'):
                    await sender.send_json_to({
                        'type': 'read', 'message_ids': ids, 'by_user_id': self.member.pk,
                    })
                    self.assertTrue(await sender.receive_nothing(timeout=0.1), ids)
                await sender.send_json_to({'type': 'read_all'})
                self.assertTrue(await sender.receive_nothing(timeout=0.1))
            finally:
                await sender.disconnect()

        async_to_sync(exercise)()
        own.refresh_from_db()
        self.assertFalse(own.is_read)

    def test_partnership_receipts_follow_the_same_rules(self):
        partnership = Partnership.objects.create(user_a=self.owner, user_b=self.member)
        conversation = Conversation.objects.create(partnership=partnership)
        outgoing = self.message(conversation=conversation)

        async def exercise():
            sender = await self.open_socket(self.owner, conversation)
            recipient = await self.open_socket(self.member, conversation)
            try:
                await sender.send_json_to({'type': 'read_all'})
                self.assertTrue(await recipient.receive_nothing(timeout=0.1))
                await recipient.send_json_to({'type': 'read', 'message_ids': [outgoing.pk]})
                self.assertEqual(await self.receipt(sender), {
                    'type': 'read', 'by_user_id': self.member.pk,
                    'conversation_id': conversation.pk, 'message_ids': [outgoing.pk],
                })
            finally:
                await recipient.disconnect()
                await sender.disconnect()

        async_to_sync(exercise)()
        outgoing.refresh_from_db()
        self.assertTrue(outgoing.is_read)

    def test_unauthorized_socket_cannot_mark_messages_read(self):
        outgoing = self.message(conversation=self.direct)

        async def exercise():
            _, token = await database_sync_to_async(AuthToken.objects.create)(self.outsider)
            socket = WebsocketCommunicator(
                URLRouter(websocket_urlpatterns), f'/ws/chat/{self.direct.pk}/?token={token}',
            )
            connected, code = await socket.connect()
            self.assertFalse(connected)
            await socket.disconnect()

        async_to_sync(exercise)()
        outgoing.refresh_from_db()
        self.assertFalse(outgoing.is_read)
