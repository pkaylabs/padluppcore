"""Reaction endpoint, access policy, serialization and socket regressions."""

import asyncio
from collections import Counter
from datetime import timedelta
from unittest.mock import AsyncMock, patch

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.test import override_settings
from django.utils import timezone
from rest_framework.test import APITestCase

from .message_models import MessageHidden, MessageReaction
from .models import Conversation, ConversationMembership, Partnership
from .test_community_acceptance import CommunityFixtures, TEST_SETTINGS


LIKE = '\U0001f44d'
HEART = '\u2764\ufe0f'


@override_settings(**TEST_SETTINGS)
class MessageReactionTests(CommunityFixtures, APITestCase):
    def setUp(self):
        super().setUp()
        direct = Conversation.objects.create()
        for user in (self.owner, self.member):
            ConversationMembership.objects.create(conversation=direct, user=user)
        partnership = Partnership.objects.create(user_a=self.owner, user_b=self.member)
        self.conversations = {
            'direct': direct,
            'partnership': Conversation.objects.create(partnership=partnership),
            'group': self.conversation,
        }

    def react(self, message, emoji=LIKE, **fields):
        with self.captureOnCommitCallbacks(execute=True):
            return self.client.post(
                f'/api-v1/community/messages/{message.pk}/react/',
                {'emoji': emoji, **fields}, format='json',
            )

    def assert_reactions(self, data, message, expected):
        self.assertEqual(data['id'], message.pk)
        self.assertEqual(data['conversation'], message.conversation_id)
        pairs = [(emoji, user.pk) for emoji, user in expected]
        self.assertCountEqual(
            [(row['emoji'], row['user']['id']) for row in data['reactions']], pairs,
        )
        self.assertCountEqual(message.reactions.values_list('emoji', 'user_id'), pairs)
        users = {user.pk: user for _, user in expected}
        for row in data['reactions']:
            user = users[row['user']['id']]
            self.assertEqual(row['user'], {'id': user.pk, 'name': user.name, 'avatar': None})

    def assert_reaction_denied(self, message, status_code, payload=None):
        before = list(message.reactions.order_by('pk').values_list('pk', 'emoji', 'user_id'))
        with patch('api.community_messaging.broadcast_message') as broadcast:
            with self.captureOnCommitCallbacks(execute=True):
                response = self.client.post(
                    f'/api-v1/community/messages/{message.pk}/react/',
                    {'emoji': LIKE} if payload is None else payload, format='json',
                )
            self.assertEqual(response.status_code, status_code, response.data)
            broadcast.assert_not_called()
        self.assertEqual(
            list(message.reactions.order_by('pk').values_list('pk', 'emoji', 'user_id')), before,
        )

    def test_participants_can_toggle_remove_and_readd_their_own_reaction(self):
        for kind, conversation in self.conversations.items():
            with self.subTest(conversation=kind):
                message = self.message(conversation=conversation)
                for expected in ([(LIKE, self.member)], [], [(LIKE, self.member)]):
                    response = self.react(message)
                    self.assertEqual(response.status_code, 200, response.data)
                    self.assertIs(response.data['can_react'], True)
                    self.assert_reactions(response.data, message, expected)
                    for prefix in ('/api-v1/messages/', '/api-v1/community/messages/'):
                        fetched = self.client.get(f'{prefix}{message.pk}/')
                        self.assertEqual(fetched.status_code, 200, fetched.data)
                        self.assertIs(fetched.data['can_react'], True)
                        self.assert_reactions(fetched.data, message, expected)

    def test_multiple_users_and_emojis_preserve_counts_and_public_identity(self):
        for kind, conversation in self.conversations.items():
            with self.subTest(conversation=kind):
                message = self.message(conversation=conversation)
                expected = []
                for user, emoji in ((self.member, LIKE), (self.owner, LIKE), (self.member, HEART)):
                    self.client.force_authenticate(user)
                    response = self.react(message, emoji)
                    self.assertEqual(response.status_code, 200, response.data)
                    expected.append((emoji, user))
                    self.assert_reactions(response.data, message, expected)
                self.assertEqual(
                    Counter(row['emoji'] for row in response.data['reactions']),
                    {LIKE: 2, HEART: 1},
                )
                response = self.react(message, LIKE)
                self.assertEqual(response.status_code, 200, response.data)
                self.assert_reactions(response.data, message, [(LIKE, self.owner), (HEART, self.member)])
                self.assertEqual(
                    Counter(row['emoji'] for row in response.data['reactions']),
                    {LIKE: 1, HEART: 1},
                )

    def test_payload_cannot_create_or_remove_another_users_reaction(self):
        for kind, conversation in self.conversations.items():
            with self.subTest(conversation=kind):
                message = self.message(conversation=conversation)
                original = MessageReaction.objects.create(message=message, user=self.owner, emoji=LIKE)
                for expected in ([(LIKE, self.owner), (LIKE, self.member)], [(LIKE, self.owner)]):
                    response = self.react(message, user=self.owner.pk, user_id=self.owner.pk)
                    self.assertEqual(response.status_code, 200, response.data)
                    self.assert_reactions(response.data, message, expected)
                    self.assertTrue(MessageReaction.objects.filter(pk=original.pk).exists())

    def test_outsiders_cannot_react_even_to_public_group_messages(self):
        self.client.force_authenticate(self.outsider)
        for kind, conversation in self.conversations.items():
            with self.subTest(conversation=kind):
                message = self.message(conversation=conversation)
                MessageReaction.objects.create(message=message, user=self.owner, emoji=LIKE)
                self.assert_reaction_denied(message, 404)

    def test_anonymous_requests_cannot_react(self):
        self.client.force_authenticate(None)
        for kind, conversation in self.conversations.items():
            with self.subTest(conversation=kind):
                self.assert_reaction_denied(self.message(conversation=conversation), 401)

    def test_hidden_messages_cannot_be_reacted_to_by_the_user_who_hid_them(self):
        for kind, conversation in self.conversations.items():
            with self.subTest(conversation=kind):
                self.client.force_authenticate(self.member)
                message = self.message(conversation=conversation)
                MessageReaction.objects.create(message=message, user=self.member, emoji=LIKE)
                MessageHidden.objects.create(message=message, user=self.member)
                self.assert_reaction_denied(message, 404)
                self.client.force_authenticate(self.owner)
                response = self.react(message, HEART)
                self.assertEqual(response.status_code, 200, response.data)
                self.assertIs(response.data['can_react'], True)
                self.assert_reactions(response.data, message, [(LIKE, self.member), (HEART, self.owner)])

    def test_sender_deleted_messages_cannot_be_reacted_to(self):
        for kind, conversation in self.conversations.items():
            with self.subTest(conversation=kind):
                message = self.message(conversation=conversation)
                MessageReaction.objects.create(message=message, user=self.member, emoji=LIKE)
                self.client.force_authenticate(self.owner)
                with self.captureOnCommitCallbacks(execute=True):
                    deleted = self.client.post('/api-v1/community/messages/delete-selection/', {
                        'ids': [message.pk], 'scope': 'everyone',
                    }, format='json')
                self.assertEqual(deleted.status_code, 200, deleted.data)
                self.client.force_authenticate(self.member)
                fetched = self.client.get(f'/api-v1/community/messages/{message.pk}/')
                self.assertEqual(fetched.status_code, 200, fetched.data)
                self.assertEqual(fetched.data['deletion_kind'], 'sender')
                self.assertIs(fetched.data['can_react'], False)
                self.assert_reactions(fetched.data, message, [])
                self.assert_reaction_denied(message, 400)

    def test_moderator_deleted_messages_cannot_be_reacted_to(self):
        message = self.message(at=timezone.now() - timedelta(hours=1))
        MessageReaction.objects.create(message=message, user=self.member, emoji=LIKE)
        self.client.force_authenticate(self.owner)
        with self.captureOnCommitCallbacks(execute=True):
            deleted = self.client.post('/api-v1/community/messages/delete-selection/', {
                'ids': [message.pk], 'scope': 'everyone', 'reason': 'Removed by moderator',
            }, format='json')
        self.assertEqual(deleted.status_code, 200, deleted.data)
        self.client.force_authenticate(self.member)
        fetched = self.client.get(f'/api-v1/community/messages/{message.pk}/')
        self.assertEqual(fetched.status_code, 200, fetched.data)
        self.assertEqual(fetched.data['deletion_kind'], 'moderator')
        self.assertIs(fetched.data['can_react'], False)
        self.assert_reactions(fetched.data, message, [])
        self.assert_reaction_denied(message, 400)

    def test_former_members_can_read_old_reactions_but_cannot_add_or_remove(self):
        message = self.message()
        MessageReaction.objects.create(message=message, user=self.member, emoji=LIKE)
        left = self.client.post(f'/api-v1/community/groups/{self.group.pk}/leave/', {
            'reason': 'Goals achieved',
        }, format='json')
        self.assertEqual(left.status_code, 200, left.data)
        for prefix in ('/api-v1/messages/', '/api-v1/community/messages/'):
            fetched = self.client.get(f'{prefix}{message.pk}/')
            self.assertEqual(fetched.status_code, 200, fetched.data)
            self.assertIs(fetched.data['can_react'], False)
            self.assert_reactions(fetched.data, message, [(LIKE, self.member)])
        self.assert_reaction_denied(message, 403)
        self.assert_reaction_denied(message, 403, {'emoji': HEART})
        self.assert_reaction_denied(self.message(text='After departure'), 404)

    def test_inactive_group_memberships_do_not_inherit_conversation_access(self):
        message = self.message()
        MessageReaction.objects.create(message=message, user=self.member, emoji=LIKE)
        for state in ('pending', 'removed', 'banned', 'rejected'):
            with self.subTest(state=state):
                self.membership.state = state
                self.membership.save(update_fields=['state'])
                self.assert_reaction_denied(message, 404)

    def test_group_messages_outside_the_history_window_cannot_be_reacted_to(self):
        message = self.message(at=self.membership.joined_at - timedelta(days=31))
        MessageReaction.objects.create(message=message, user=self.owner, emoji=LIKE)
        self.assert_reaction_denied(message, 404)

    def test_resource_only_history_disables_reactions_without_disabling_visible_resources(self):
        old = self.message(
            text='Private old body https://example.com/old',
            at=self.membership.joined_at - timedelta(days=31),
        )
        current = self.message(text='Current body https://example.com/current')
        for message in (old, current):
            MessageReaction.objects.create(message=message, user=self.owner, emoji=LIKE)
        for path in (
            f'/api-v1/conversations/{self.conversation.pk}/resources/',
            f'/api-v1/community/groups/{self.group.pk}/resources/',
        ):
            with self.subTest(path=path):
                response = self.client.get(path, {'type': 'links'})
                resources = {row['id']: row for row in self.rows(response)}
                self.assertEqual(set(resources), {old.pk, current.pk})
                self.assertIs(resources[old.pk]['can_react'], False)
                self.assertEqual(resources[old.pk]['reactions'], [])
                self.assertEqual(resources[old.pk]['text'], '')
                self.assertEqual(resources[old.pk]['links'], ['https://example.com/old'])
                self.assertIs(resources[current.pk]['can_react'], True)
                self.assert_reactions(resources[current.pk], current, [(LIKE, self.owner)])
        self.assert_reaction_denied(old, 404)
        self.assertEqual(list(old.reactions.values_list('emoji', 'user_id')), [(LIKE, self.owner.pk)])

    def test_missing_blank_and_oversized_emoji_are_rejected_without_mutation(self):
        payloads = ({}, {'emoji': ''}, {'emoji': ' \t\n'}, {'emoji': LIKE * 33})
        for kind, conversation in self.conversations.items():
            message = self.message(conversation=conversation)
            MessageReaction.objects.create(message=message, user=self.member, emoji=LIKE)
            for payload in payloads:
                with self.subTest(conversation=kind, payload=payload):
                    self.assert_reaction_denied(message, 400, payload)

    def test_emoji_whitespace_is_normalized_before_toggling(self):
        for kind, conversation in self.conversations.items():
            with self.subTest(conversation=kind):
                message = self.message(conversation=conversation)
                added = self.react(message, f' \t{HEART}\n')
                self.assertEqual(added.status_code, 200, added.data)
                self.assert_reactions(added.data, message, [(HEART, self.member)])
                removed = self.react(message, HEART)
                self.assertEqual(removed.status_code, 200, removed.data)
                self.assert_reactions(removed.data, message, [])

    def test_add_and_remove_broadcast_message_updated_with_fresh_reactions(self):
        layer = get_channel_layer()
        for kind, conversation in self.conversations.items():
            with self.subTest(conversation=kind):
                message = self.message(conversation=conversation)
                channel = async_to_sync(layer.new_channel)()
                group = f'chat_{conversation.pk}'
                async_to_sync(layer.group_add)(group, channel)
                self.addCleanup(async_to_sync(layer.group_discard), group, channel)
                consumer = self.socket(user=self.owner, conversation=conversation)

                async def receive_update():
                    return await asyncio.wait_for(layer.receive(channel), timeout=1)

                for expected in ([(LIKE, self.member)], []):
                    response = self.react(message)
                    self.assertEqual(response.status_code, 200, response.data)
                    event = async_to_sync(receive_update)()
                    self.assertEqual(event, {'type': 'chat.message.updated', 'message_id': message.pk})
                    with patch.object(consumer, 'send_json', new_callable=AsyncMock) as send:
                        async_to_sync(consumer.chat_message_updated)(event)
                    send.assert_awaited_once()
                    payload = send.call_args.args[0]
                    self.assertEqual(payload['type'], 'message_updated')
                    self.assertIs(payload['message']['can_react'], True)
                    self.assert_reactions(payload['message'], message, expected)
