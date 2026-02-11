from rest_framework import permissions
from rest_framework.response import Response
from rest_framework.views import APIView

from drf_spectacular.utils import extend_schema


class WebSocketDocsView(APIView):
	"""Fake REST endpoint used only for documenting WebSocket channels in OpenAPI/Swagger."""

	permission_classes = [permissions.AllowAny]

	@extend_schema(
		description=(
			"WebSocket channels (documentation-only).\n\n"
			"All WebSockets require `wss://` in production and authenticate using a Knox token "
			"passed as a query param: `?token=<token>`.\n\n"
			"### Channels\n\n"
			"#### 1) Conversations list\n"
			"- URL: `wss://api.padlupp.com/ws/conversations/?token=<token>`\n"
			"- Server -> Client (initial):\n"
			"  ```json\n  {\"type\":\"conversations\",\"conversations\":[{...}]}\n  ```\n"
			"- Server -> Client (updates):\n"
			"  ```json\n  {\"type\":\"conversation_update\",\"conversation\":{...}}\n  ```\n\n"
			"Conversation payload shape:\n"
			"```json\n"
			"{\n"
			"  \"id\": 123,\n"
			"  \"partnership\": 456,\n"
			"  \"last_message\": { ...MessageSerializer... } | null,\n"
			"  \"unread_count\": 3,\n"
			"  \"created_at\": \"2026-02-04T12:34:56Z\",\n"
			"  \"updated_at\": \"2026-02-04T12:40:00Z\"\n"
			"}\n"
			"```\n\n"
			"Notes:\n"
			"- Any `user.avatar` field returned by serializers is a full absolute URL (e.g. `https://api.padlupp.com/assets/avatars/...jpg`).\n\n"
			"#### 2) Chat (per conversation)\n"
			"- URL: `wss://api.padlupp.com/ws/chat/<conversation_id>/?token=<token>`\n\n"
			"On connect the server sends history:\n"
			"```json\n  {\"type\":\"history\",\"messages\":[{...}]}\n```\n\n"
			"Client -> Server messages:\n"
			"- Send message:\n"
			"  ```json\n  {\"type\":\"message\",\"text\":\"Hello\"}\n  ```\n"
			"- Typing:\n"
			"  ```json\n  {\"type\":\"typing\",\"is_typing\":true}\n  ```\n"
			"- Delivered ack (after receiving a message):\n"
			"  ```json\n  {\"type\":\"delivered\",\"message_id\":123}\n  ```\n"
			"- Read receipts (optional):\n"
			"  ```json\n  {\"type\":\"read\",\"message_ids\":[1,2,3]}\n  ```\n"
			"  ```json\n  {\"type\":\"read_all\"}\n  ```\n\n"
			"Server -> Client events (chat):\n"
			"- New message: the serialized message dict (backward-compatible)\n"
			"- Ack to sender: `{'type':'ack','ack':'received','message_id':<id>}`\n"
			"- Typing: `{'type':'typing','user_id':<id>,'is_typing':<bool>}`\n"
			"- Presence: `{'type':'presence','online_user_ids':[...]} `\n"
			"- Delivered: `{'type':'delivered','message_id':<id>,'by_user_id':<id>}`\n"
			"- Read: `{'type':'read','message_ids':[...],'by_user_id':<id>}`\n"
			"- Read all: `{'type':'read_all','by_user_id':<id>}`\n"
		),
		responses={200: dict},
		tags=["websockets"],
	)
	def get(self, request):
		# Keep the runtime response minimal. The details live in the schema description.
		return Response({
			"detail": "WebSocket documentation only. See OpenAPI description for channel details.",
			"channels": [
				"wss://api.padlupp.com/ws/conversations/?token=<token>",
				"wss://api.padlupp.com/ws/chat/<conversation_id>/?token=<token>",
			],
		})
