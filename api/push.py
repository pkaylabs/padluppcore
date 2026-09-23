from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import logging
from pathlib import Path
from threading import Lock

import requests
from django.conf import settings
from django.db import close_old_connections
from google.auth.transport.requests import Request
from google.oauth2 import service_account

from .models import DevicePushToken, Notification

logger = logging.getLogger(__name__)

_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix='padlupp-push')
_credentials = None
_credentials_lock = Lock()
_scope = 'https://www.googleapis.com/auth/firebase.messaging'


def enqueue_notification_push(notification_id: int) -> None:
	if not getattr(settings, 'FIREBASE_PUSH_ENABLED', False):
		return
	_executor.submit(send_notification_push, notification_id)


def _load_credentials():
	global _credentials
	with _credentials_lock:
		if _credentials is not None:
			return _credentials
		service_account_json = getattr(settings, 'FIREBASE_SERVICE_ACCOUNT_JSON', '')
		service_account_file = getattr(settings, 'FIREBASE_SERVICE_ACCOUNT_FILE', '')
		if service_account_json:
			info = json.loads(service_account_json)
			_credentials = service_account.Credentials.from_service_account_info(info, scopes=[_scope])
		elif service_account_file:
			path = Path(service_account_file)
			_credentials = service_account.Credentials.from_service_account_file(path, scopes=[_scope])
		else:
			raise RuntimeError('Firebase service account credentials are not configured.')
		return _credentials


def _access_token() -> tuple[str, str]:
	credentials = _load_credentials()
	with _credentials_lock:
		if not credentials.valid or credentials.expired or not credentials.token:
			credentials.refresh(Request())
	project_id = getattr(settings, 'FIREBASE_PROJECT_ID', '') or credentials.project_id
	if not project_id:
		raise RuntimeError('Firebase project ID is not configured.')
	return credentials.token, project_id


def _notification_content(notification: Notification) -> tuple[str, str, str]:
	payload = notification.payload or {}
	notification_type = (notification.type or '').strip()
	if notification_type == 'new_message':
		sender_name = payload.get('sender_name') or 'Someone'
		return f'New message from {sender_name}', payload.get('preview') or 'Open Padlupp to reply.', f"/messages/{payload.get('conversation_id', '')}"
	if notification_type == 'buddy_request_received':
		from_name = payload.get('from_user_name') or 'Someone'
		return 'New connection request', payload.get('message') or f'{from_name} wants to connect with you.', '/buddies'
	if notification_type in {'new_match', 'buddy_request_accepted'}:
		return payload.get('title') or 'Accountability update', payload.get('message') or 'You have a new buddy update.', '/buddies'
	if notification_type == 'goal_joined':
		goal_id = payload.get('goal_id') or ''
		return payload.get('title') or 'Someone joined your goal', payload.get('message') or 'Open Padlupp to welcome them.', f'/goals/{goal_id}'
	if notification_type in {'checkin_reminder', 'subtask_reminder'}:
		return 'Time to check in', payload.get('message') or 'Keep your momentum going with a quick update.', f"/goals/{payload.get('goal_id', '')}"
	if notification_type == 'inactivity_nudge':
		return payload.get('title') or 'Ready for your next step?', payload.get('message') or 'A small update today can restart your momentum.', '/goals'
	if notification_type in {'new_task', 'review_requested', 'evidence_submitted', 'task_approved', 'task_changes_requested', 'goal_shared'}:
		goal_id = payload.get('goal_id')
		path = f'/goals/{goal_id}' if goal_id else '/notifications'
		return payload.get('title') or 'Goal update', payload.get('message') or 'There is an update waiting for you.', path
	return payload.get('title') or 'Padlupp', payload.get('message') or payload.get('detail') or 'You have a new notification.', '/notifications'


def _is_invalid_token(response: requests.Response) -> bool:
	if response.status_code in {404, 410}:
		return True
	try:
		details = response.json().get('error', {}).get('details', [])
	except (ValueError, AttributeError):
		return False
	return any(detail.get('errorCode') in {'UNREGISTERED', 'INVALID_ARGUMENT'} for detail in details if isinstance(detail, dict))


def send_notification_push(notification_id: int) -> None:
	close_old_connections()
	try:
		notification = Notification.objects.select_related('user').get(id=notification_id)
		tokens = list(DevicePushToken.objects.filter(user=notification.user, is_active=True))
		if not tokens:
			return
		access_token, project_id = _access_token()
		title, body, path = _notification_content(notification)
		url = f'https://fcm.googleapis.com/v1/projects/{project_id}/messages:send'
		headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}
		base_data = {
			'notification_id': str(notification.id),
			'type': notification.type or '',
			'path': path,
		}
		for device in tokens:
			response = requests.post(
				url,
				headers=headers,
				json={
					'message': {
						'token': device.token,
						'notification': {'title': str(title), 'body': str(body)},
						'data': base_data,
						'android': {'priority': 'high', 'notification': {'channel_id': 'padlupp_notifications'}},
						'apns': {'payload': {'aps': {'sound': 'default'}}},
					},
				},
				timeout=12,
			)
			if response.ok:
				continue
			if _is_invalid_token(response):
				DevicePushToken.objects.filter(id=device.id).update(is_active=False)
			else:
				logger.warning('FCM rejected push for notification %s with status %s', notification.id, response.status_code)
	except Notification.DoesNotExist:
		return
	except Exception:
		logger.exception('Failed to send Firebase push notification %s', notification_id)
	finally:
		close_old_connections()
