from django.contrib.auth import authenticate
from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.db import IntegrityError
from django.db import models
from django.db import transaction
from django.http import FileResponse
import secrets
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from knox.models import AuthToken
from rest_framework import mixins, permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.parsers import FormParser, MultiPartParser
from drf_spectacular.utils import OpenApiParameter, OpenApiTypes, extend_schema
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle

from datetime import timedelta, datetime
from django.utils import timezone

from google.auth.transport import requests as google_requests
from google.oauth2 import id_token as google_id_token

from padluppcore.utils.email import EmailSendError, send_mailgun_email
from .activity import dt_to_local_date, get_user_tzinfo, record_user_activity

from accounts.models import AccountDeletionRequest, PasswordResetOTP, User
from .models import BuddyRequest, Conversation, ConversationMembership, DevicePushToken, Evidence, Event, Goal, GoalCheckin, GoalCheckinBadge, GoalCheckinEvidenceView, GoalCheckinReaction, GoalMembership, Match, Message, Notification, Partnership, Profile, SubTask, Task, TimerSession, UserDailyActivity, Waitlister
from .matching import compatibility_details, profile_is_complete
from .serializers import (
	BuddyConnectSerializer,
	BuddyFinderProfileSerializer,
	BuddyRequestSerializer,
	BuddyRequestActionResponseSerializer,
	BuddyProfileResponseSerializer,
	ConversationMediaSerializer,
	DetailResponseSerializer,
	UserAvatarRequestSerializer,
	ProfileExperienceRequestSerializer,
	TaskRequestChangesRequestSerializer,
	NotificationMarkAllReadResponseSerializer,
	ConversationSerializer,
	EvidenceSerializer,
	EventxSerializer,
	GoalSerializer,
	GoalCheckinReactionRequestSerializer,
	GoalCheckinSerializer,
	GoalJoinRequestSerializer,
	GoalJoinResponseSerializer,
	GoalShareRequestSerializer,
	GoalShareResponseSerializer,
	PublicGoalPreviewSerializer,
	MatchSerializer,
	NotificationSerializer,
	PartnershipSerializer,
	ProfileSerializer,
	PublicUserSerializer,
	SubTaskSerializer,
	TaskSerializer,
	TimerSessionSerializer,
	MessageSerializer,
	UserSerializer,
	WaitlisterSerializer,
	LongestStreakResponseSerializer,
	ConversationRenameRequestSerializer,
)
from .serializers import (
	GoogleAuthRequestSerializer,
	GoogleAuthResponseSerializer,
	DeleteAccountRequestSerializer,
	ForgotPasswordRequestOtpSerializer,
	ForgotPasswordResetPasswordSerializer,
	ForgotPasswordVerifyOtpResponseSerializer,
	ForgotPasswordVerifyOtpSerializer,
	InviteUserRequestSerializer,
	InviteUserResponseSerializer,
	LoginRequestSerializer,
	LoginResponseSerializer,
	UserUpdateRequestSerializer,
	NotificationPreferencesSerializer,
	DevicePushTokenRegisterSerializer,
	DevicePushTokenUnregisterSerializer,
)


WAITLIST_BETA_MESSAGE = (
	"Thanks for trying Padlupp. We're currently in a limited beta and only waitlisted "
	"users can sign up or sign in. Join the waitlist and we'll notify you when we open to everyone."
)


def _app_base_url() -> str:
	return (getattr(settings, 'PADLUPP_APP_URL', '') or 'https://app.padlupp.com').rstrip('/')


def _goal_direct_link(goal_id: int) -> str:
	return f'{_app_base_url()}/goals/{goal_id}'


def _goal_invite_link(shared_id) -> str:
	return f'{_app_base_url()}/goals'


def _user_is_member_of_conversation(user_id: int, conversation: Conversation) -> bool:
	if conversation.members.filter(id=user_id).exists():
		return True
	if conversation.partnership_id and user_id in [conversation.partnership.user_a_id, conversation.partnership.user_b_id]:
		return True
	if conversation.goal_id and conversation.goal.members.filter(id=user_id).exists():
		return True
	return False


def _goal_member_ids(goal: Goal) -> list[int]:
	ids = list(goal.members.values_list('id', flat=True))
	if goal.user_id and goal.user_id not in ids:
		ids.append(goal.user_id)
	if goal.partnership_id:
		for uid in [goal.partnership.user_a_id, goal.partnership.user_b_id]:
			if uid and uid not in ids:
				ids.append(uid)
	return ids


def _add_goal_member(goal: Goal, user: User, added_by: User | None = None) -> bool:
	membership, created = GoalMembership.objects.get_or_create(
		goal=goal,
		user=user,
		defaults={'added_by': added_by},
	)
	if not created and added_by and not membership.added_by_id:
		membership.added_by = added_by
		membership.save(update_fields=['added_by', 'updated_at'])
	return created


def _add_conversation_member(conversation: Conversation, user: User, added_by: User | None = None) -> bool:
	membership, created = ConversationMembership.objects.get_or_create(
		conversation=conversation,
		user=user,
		defaults={'added_by': added_by},
	)
	if not created and added_by and not membership.added_by_id:
		membership.added_by = added_by
		membership.save(update_fields=['added_by', 'updated_at'])
	return created


def _ensure_goal_conversation(goal: Goal, added_by: User | None = None) -> Conversation:
	conversation, _ = Conversation.objects.get_or_create(
		goal=goal,
		defaults={'is_group': True, 'name': goal.title},
	)
	changed_fields = []
	if not conversation.is_group:
		conversation.is_group = True
		changed_fields.append('is_group')
	if not (conversation.name or '').strip():
		conversation.name = goal.title
		changed_fields.append('name')
	if changed_fields:
		conversation.save(update_fields=[*changed_fields, 'updated_at'])
	for member_id in _goal_member_ids(goal):
		member = User.objects.filter(id=member_id, is_active=True, deleted=False).first()
		if member:
			_add_conversation_member(conversation, member, added_by)
	return conversation


def _normalize_email(email: str | None) -> str:
	return (email or '').strip().lower()


def _waitlist_gate_response(email: str | None):
	"""Return a Response if waitlist gating blocks the request, else None."""
	if not getattr(settings, 'BETA_WAITLIST_ONLY', True):
		return None
	if not email:
		return Response({'detail': WAITLIST_BETA_MESSAGE}, status=status.HTTP_403_FORBIDDEN)
	if Waitlister.objects.filter(email__iexact=email).exists():
		return None
	return Response({'detail': WAITLIST_BETA_MESSAGE}, status=status.HTTP_403_FORBIDDEN)


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


def _generate_password_reset_otp() -> str:
	# 6-digit numeric OTP
	return f"{secrets.randbelow(1_000_000):06d}"


def _generate_password_reset_token() -> str:
	# High-entropy token returned once to the client.
	return secrets.token_urlsafe(32)


def _set_last_login(user: User, at: datetime | None = None) -> datetime:
	"""Persist last_login for token-based auth flows.

	Django updates `last_login` when using `django.contrib.auth.login()`, but this
	codebase uses token auth (Knox) and `authenticate()` directly.
	"""
	now = at or timezone.now()
	User.objects.filter(pk=user.pk).update(last_login=now)
	# Keep in-memory object consistent for the current request.
	user.last_login = now
	record_user_activity(user, at=now, source='login')
	return now


class BuddyViewSet(viewsets.ViewSet):
	permission_classes = [permissions.IsAuthenticated]

	def _buddy_user_ids(self, user):
		pairs = Partnership.objects.filter(
			models.Q(user_a=user) | models.Q(user_b=user)
		).values_list('user_a_id', 'user_b_id')
		buddy_ids = set()
		for a_id, b_id in pairs:
			buddy_ids.add(a_id)
			buddy_ids.add(b_id)
		buddy_ids.discard(user.id)
		return buddy_ids

	@extend_schema(
		responses={200: BuddyFinderProfileSerializer(many=True)},
		description="List profiles with similar experience and pending requests."
	)
	@action(detail=False, methods=['get'], url_path='finder')
	def finder(self, request):
		"""List eligible profiles ordered by stable compatibility score."""
		user = request.user
		category = (request.query_params.get('category') or '').strip().casefold()
		profile, _ = Profile.objects.get_or_create(user=user)
		buddy_user_ids = self._buddy_user_ids(user)

		pending_requests = BuddyRequest.objects.filter(
			from_user=user,
			status=BuddyRequest.STATUS_PENDING,
		)
		pending_to_user_ids = set(pending_requests.values_list('to_user_id', flat=True))
		pending_request_id_by_to_user_id = {
			row['to_user_id']: row['id']
			for row in pending_requests.values('id', 'to_user_id')
		}

		# Likes and passes cool down after 30 days. This prevents immediate repeats
		# without making a person permanently undiscoverable.
		recently_swiped_ids = Match.objects.filter(
			from_user=user,
			created_at__gte=timezone.now() - timedelta(days=30),
		).values_list('to_user_id', flat=True)
		excluded_user_ids = set(buddy_user_ids) | set(recently_swiped_ids) | {user.id}

		qs = (
			Profile.objects.select_related('user')
			.filter(user__is_active=True, user__deleted=False)
			.exclude(user_id__in=excluded_user_ids)
		)
		profiles = list(qs)
		if category:
			profiles = [
				candidate for candidate in profiles
				if category in ' '.join([
					candidate.experience or '',
					candidate.interests or '',
					' '.join(candidate.focus_areas or []),
				]).casefold()
				or candidate.user_id in pending_to_user_ids
			]
		if any([
			(profile.experience or '').strip(),
			(profile.interests or '').strip(),
			profile.focus_areas,
			profile.availability,
			profile.communication_styles,
		]):
			profiles = [
				candidate for candidate in profiles
				if compatibility_details(profile, candidate)['score'] > 0
				or candidate.user_id in pending_to_user_ids
			]
		profiles.sort(
			key=lambda candidate: (
				-compatibility_details(profile, candidate)['score'],
				-candidate.created_at.timestamp(),
				candidate.user_id,
			)
		)
		serializer = BuddyFinderProfileSerializer(
			profiles,
			many=True,
			context={
				'request': request,
				'source_profile': profile,
				'pending_to_user_ids': pending_to_user_ids,
				'pending_request_id_by_to_user_id': pending_request_id_by_to_user_id,
			},
		)
		return Response(serializer.data)


	@extend_schema(
		request=BuddyConnectSerializer,
		responses={
			201: BuddyRequestSerializer,
			400: DetailResponseSerializer,
		},
		description="Send a buddy connection request to another user."
	)
	@action(detail=False, methods=['post'], url_path='connect')
	def connect(self, request):
		"""Send a buddy connection request to another user."""
		serializer = BuddyConnectSerializer(data=request.data)
		serializer.is_valid(raise_exception=True)
		to_user = serializer.validated_data['to_user']
		message = (serializer.validated_data.get('message') or '').strip()
		from_user = request.user

		if to_user.id == from_user.id:
			return Response({'detail': 'Cannot connect to yourself.'}, status=status.HTTP_400_BAD_REQUEST)

		# Block if already buddies (partnership exists)
		user_a, user_b = sorted([from_user, to_user], key=lambda u: u.id)
		if Partnership.objects.filter(user_a=user_a, user_b=user_b).exists():
			return Response({'detail': 'You are already connected.'}, status=status.HTTP_400_BAD_REQUEST)

		# Upsert request (prevents duplicates via unique_together)
		buddy_request, created = BuddyRequest.objects.get_or_create(
			from_user=from_user,
			to_user=to_user,
			defaults={'status': BuddyRequest.STATUS_PENDING, 'message': message},
		)
		if not created:
			if buddy_request.status == BuddyRequest.STATUS_PENDING:
				return Response({'detail': 'Connection request already pending.'}, status=status.HTTP_400_BAD_REQUEST)
			# If previously rejected/accepted, reset to pending
			buddy_request.status = BuddyRequest.STATUS_PENDING
			buddy_request.responded_at = None
			buddy_request.message = message
			buddy_request.save(update_fields=['status', 'responded_at', 'message', 'updated_at'])

		# Best-effort email notification to recipient.
		to_email = (getattr(to_user, 'preferred_notification_email', None) or getattr(to_user, 'email', '') or '').strip()
		if to_user.notify_on_new_match and settings.EMAIL_NOTIFICATIONS_ENABLED and to_email:
			from_name = (getattr(from_user, 'name', '') or '').strip() or 'Someone'
			platform_url = _app_base_url()
			subject = 'New connection request on Padlupp'
			text = f"{from_name} sent you a connection request on Padlupp.\n\n"
			if message:
				text += f"Message: {message}\n\n"
			text += f"Open the app to respond: {platform_url}"
			try:
				send_mailgun_email(
					to_email=to_email,
					subject=subject,
					text=text,
					tags=['buddy_request'],
				)
			except Exception:
				# Best-effort only: don't block the request on email issues.
				pass

		return Response(BuddyRequestSerializer(buddy_request, context={'request': request}).data, status=status.HTTP_201_CREATED)


	@extend_schema(
		responses={200: BuddyRequestSerializer(many=True)},
		description="List pending buddy requests sent to the current user."
	)
	@action(detail=False, methods=['get'], url_path='invitations')
	def invitations(self, request):
		"""List pending buddy requests sent to the current user."""
		qs = BuddyRequest.objects.filter(
			to_user=request.user,
			status=BuddyRequest.STATUS_PENDING,
		).order_by('-created_at')
		return Response(BuddyRequestSerializer(qs, many=True, context={'request': request}).data)


	@extend_schema(
		responses={
			200: BuddyRequestActionResponseSerializer,
			404: DetailResponseSerializer,
		},
		description="Accept a buddy request and create a partnership."
	)
	@action(detail=True, methods=['post'], url_path='accept')
	def accept(self, request, pk=None):
		"""Accept a buddy request (creates a Partnership)."""
		buddy_request = BuddyRequest.objects.filter(
			id=pk,
			to_user=request.user,
			status=BuddyRequest.STATUS_PENDING,
		).first()
		if not buddy_request:
			return Response({'detail': 'Invitation not found.'}, status=status.HTTP_404_NOT_FOUND)

		buddy_request.status = BuddyRequest.STATUS_ACCEPTED
		buddy_request.responded_at = models.functions.Now()
		buddy_request.save(update_fields=['status', 'responded_at', 'updated_at'])

		user_a, user_b = sorted([buddy_request.from_user, buddy_request.to_user], key=lambda u: u.id)
		partnership, _ = Partnership.objects.get_or_create(user_a=user_a, user_b=user_b)
		# Ensure a conversation exists (matches app behavior)
		conversation, _ = Conversation.objects.get_or_create(partnership=partnership)
		_add_conversation_member(conversation, user_a, request.user)
		_add_conversation_member(conversation, user_b, request.user)
		if buddy_request.message.strip() and not conversation.messages.exists():
			Message.objects.create(
				conversation=conversation,
				sender=buddy_request.from_user,
				text=buddy_request.message.strip(),
			)
		# Notify both users' conversations websockets so the new conversation appears.
		self._broadcast_conversation_update(conversation_id=conversation.id, user_ids=[user_a.id, user_b.id])

		# Notify requester that their connection request was accepted.
		if buddy_request.from_user.notify_on_new_match:
			Notification.objects.create(
				user=buddy_request.from_user,
				type='buddy_request_accepted',
				payload={'partner_id': buddy_request.to_user_id, 'partnership_id': partnership.id},
			)

		return Response({'detail': 'Accepted.', 'partnership_id': partnership.id}, status=status.HTTP_200_OK)

	def _broadcast_conversation_update(self, *, conversation_id: int, user_ids: list[int]):
		"""Best-effort realtime update for ws/conversations/."""
		channel_layer = get_channel_layer()
		if not channel_layer:
			return
		last_msg = (
			Message.objects.select_related('sender')
			.filter(conversation_id=conversation_id)
			.order_by('-created_at')
			.first()
		)
		last_message_payload = MessageSerializer(last_msg, context={'request': getattr(self, 'request', None)}).data if last_msg else None
		conv = Conversation.objects.get(id=conversation_id)
		for uid in user_ids:
			unread_count = (
				Message.objects.filter(conversation_id=conversation_id, is_read=False)
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


	@extend_schema(
		responses={
			200: BuddyRequestActionResponseSerializer,
			404: DetailResponseSerializer,
		},
		description="Reject a buddy request."
	)
	@action(detail=True, methods=['post'], url_path='reject')
	def reject(self, request, pk=None):
		"""Reject a buddy request."""
		buddy_request = BuddyRequest.objects.filter(
			id=pk,
			to_user=request.user,
			status=BuddyRequest.STATUS_PENDING,
		).first()
		if not buddy_request:
			return Response({'detail': 'Invitation not found.'}, status=status.HTTP_404_NOT_FOUND)

		buddy_request.status = BuddyRequest.STATUS_REJECTED
		buddy_request.responded_at = models.functions.Now()
		buddy_request.save(update_fields=['status', 'responded_at', 'updated_at'])
		return Response({'detail': 'Rejected.'}, status=status.HTTP_200_OK)


	@extend_schema(
		responses={200: BuddyProfileResponseSerializer, 404: DetailResponseSerializer},
		description='Get another user\'s buddy profile.'
	)
	@action(detail=False, methods=['get'], url_path=r'profile/(?P<user_id>[^/.]+)')
	def profile(self, request, user_id=None):
		if not user_id:
			return Response({'detail': 'user_id is required.'}, status=status.HTTP_400_BAD_REQUEST)
		if str(request.user.id) == str(user_id):
			return Response({'detail': 'Use your own profile endpoint for the current user.'}, status=status.HTTP_400_BAD_REQUEST)
		other_user = User.objects.filter(id=user_id, deleted=False).first()
		if not other_user:
			return Response({'detail': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
		profile, _ = Profile.objects.get_or_create(user=other_user)
		return Response(BuddyProfileResponseSerializer({'user': other_user, 'profile': profile}, context={'request': request}).data)

	@extend_schema(
		responses={200: ProfileSerializer(many=True)},
		description="Return the current user's buddy connections as profiles."
	)
	@action(detail=False, methods=['get'], url_path='connections')
	def connections(self, request):
		"""Return current user's buddy connections as profiles."""
		user = request.user
		buddy_ids = self._buddy_user_ids(user)
		qs = Profile.objects.filter(user_id__in=buddy_ids).order_by('-created_at')
		return Response(ProfileSerializer(qs, many=True, context={'request': request}).data)

	@extend_schema(
		parameters=[
			OpenApiParameter(
				name='query',
				type=OpenApiTypes.STR,
				location=OpenApiParameter.QUERY,
				required=True,
				description='Search text. Split into words; matches buddies where name contains any word.',
			),
		],
		responses={200: ProfileSerializer(many=True), 400: DetailResponseSerializer},
		description=(
			"Search within the current user's buddy connections by name. "
			"Splits `query` into words and matches if any word appears in the buddy's name."
		),
	)
	@action(detail=False, methods=['get'], url_path='search')
	def search(self, request):
		query = (request.query_params.get('query') or request.data.get('query') or '').strip()
		if not query:
			return Response({'detail': 'query is required.'}, status=status.HTTP_400_BAD_REQUEST)

		words = [w.strip(' ,.;:!"\'()[]{}').lower() for w in query.split()]
		words = [w for w in words if w]
		if not words:
			return Response({'detail': 'query is required.'}, status=status.HTTP_400_BAD_REQUEST)

		user = request.user
		# buddy_ids = self._buddy_user_ids(user)
		name_q = models.Q()
		email_q = models.Q()
		for w in words:
			name_q |= models.Q(user__name__icontains=w)
			email_q |= models.Q(user__email__icontains=w)

		qs = (
			Profile.objects.select_related('user')
			# .filter(user_id__in=buddy_ids)
			.filter(name_q | email_q)
			.distinct()
			.order_by('-created_at')
		)
		return Response(ProfileSerializer(qs, many=True, context={'request': request}).data)


class EventViewSet(viewsets.ModelViewSet):
	serializer_class = EventxSerializer
	permission_classes = [permissions.IsAuthenticated]

	def get_queryset(self):
		'''This will get events where the user is either the creator or a participant.'''
		user = self.request.user
		return (
			Event.objects.filter(models.Q(creator=user) | models.Q(participants=user))
			.distinct()
			.order_by('-start_date', '-start_time', '-created_at')
		)

	def perform_create(self, serializer):
		'''Create event with the current user as creator.'''
		serializer.save(creator=self.request.user)

	def perform_update(self, serializer):
		'''Only the creator can update the event.'''
		instance = self.get_object()
		if instance.creator_id != self.request.user.id:
			raise PermissionDenied('Only the creator can update this event.')
		serializer.save()

	def perform_destroy(self, instance):
		'''Only the creator can delete the event.'''
		if instance.creator_id != self.request.user.id:
			raise PermissionDenied('Only the creator can delete this event.')
		instance.delete()

	@extend_schema(
		responses={200: EventxSerializer(many=True)},
		description='Get events created by the user.'
	)
	@action(detail=False, methods=['get'], url_path='created')
	def created(self, request):
		'''Get events created by the user.'''
		qs = Event.objects.filter(creator=request.user).order_by('-start_date', '-start_time', '-created_at')
		page = self.paginate_queryset(qs)
		serializer = self.get_serializer(page or qs, many=True)
		if page is not None:
			return self.get_paginated_response(serializer.data)
		return Response(serializer.data)

	@extend_schema(
		responses={200: EventxSerializer(many=True)},
		description='Get events where the user is a participant.'
	)
	@action(detail=False, methods=['get'], url_path='participating')
	def participating(self, request):
		'''Get events where the user is a participant (not creator).'''
		qs = (
			Event.objects.filter(participants=request.user)
			.distinct()
			.order_by('-start_date', '-start_time', '-created_at')
		)
		page = self.paginate_queryset(qs)
		serializer = self.get_serializer(page or qs, many=True)
		if page is not None:
			return self.get_paginated_response(serializer.data)
		return Response(serializer.data)

	@extend_schema(
		responses={200: EventxSerializer},
		description='Join the event as a participant.'
	)
	@action(detail=True, methods=['post'], url_path='join')
	def join(self, request, pk=None):
		'''Join the event as a participant.'''
		event = self.get_object()
		event.participants.add(request.user)
		return Response(self.get_serializer(event).data, status=status.HTTP_200_OK)


class OnboardingViewSet(viewsets.ViewSet):
	permission_classes = [permissions.AllowAny]

	def get_throttles(self):
		if self.action == 'register':
			self.throttle_scope = 'registration'
			return [ScopedRateThrottle()]
		return super().get_throttles()

	from .serializers import RegisterRequestSerializer, RegisterResponseSerializer

	@extend_schema(
		request=RegisterRequestSerializer,
		responses={
			201: RegisterResponseSerializer,
			400: RegisterResponseSerializer,
		},
		description="Register a new user. Returns user info and token."
	)
	@action(detail=False, methods=['post'])
	def register(self, request):
		email = _normalize_email(request.data.get('email'))
		password = request.data.get('password')
		name = request.data.get('name')
		phone = request.data.get('phone')

		if not email or not password or not name:
			return Response({'detail': 'email, password and name are required.'}, status=status.HTTP_400_BAD_REQUEST)

		gate = _waitlist_gate_response(email)
		if gate is not None:
			return gate

		if User.objects.filter(email=email).exists():
			return Response({'detail': 'Email already in use.'}, status=status.HTTP_400_BAD_REQUEST)

		user = User.objects.create_user(email=email, password=password, name=name, phone=phone)
		Profile.objects.get_or_create(user=user)
		# auto-login after registration
		_set_last_login(user)
		token = AuthToken.objects.create(user)[1]
		return Response({'user': UserSerializer(user, context={'request': request}).data, 'token': token}, status=status.HTTP_201_CREATED)

	@extend_schema(
		responses={200: ProfileSerializer},
		description='Get current user profile.'
	)
	@action(detail=False, methods=['get'], permission_classes=[permissions.IsAuthenticated])
	def profile(self, request):
		profile, _ = Profile.objects.get_or_create(user=request.user)
		return Response(ProfileSerializer(profile, context={'request': request}).data)

	@extend_schema(
		request=ProfileSerializer,
		responses={200: ProfileSerializer},
		description='Update entire profile.'
	)
	@profile.mapping.put
	def update_profile(self, request):
		profile, _ = Profile.objects.get_or_create(user=request.user)
		serializer = ProfileSerializer(profile, data=request.data, context={'request': request})
		serializer.is_valid(raise_exception=True)
		serializer.save()
		return Response(serializer.data)

	@extend_schema(
		request=ProfileSerializer,
		responses={200: ProfileSerializer},
		description='Partially update profile.'
	)
	@profile.mapping.patch
	def partial_update_profile(self, request):
		profile, _ = Profile.objects.get_or_create(user=request.user)
		serializer = ProfileSerializer(profile, data=request.data, partial=True, context={'request': request})
		serializer.is_valid(raise_exception=True)
		serializer.save()
		return Response(serializer.data)
	
	@extend_schema(
		request=UserAvatarRequestSerializer,
		responses={200: UserSerializer, 400: DetailResponseSerializer},
		description='Set avatar for current user.'
	)
	@action(
		detail=False,
		methods=['patch'],
		url_path='user-avatar',
		permission_classes=[permissions.IsAuthenticated],
		parser_classes=[MultiPartParser, FormParser],
	)
	def user_avatar(self, request):
		user = request.user
		avatar = request.data.get('avatar')
		if not avatar:
			return Response({'detail': 'avatar is required.'}, status=status.HTTP_400_BAD_REQUEST)
		user.avatar = avatar
		user.save(update_fields=['avatar'])
		return Response(UserSerializer(user, context={'request': request}).data)
	
	@extend_schema(
		request=ProfileExperienceRequestSerializer,
		responses={200: ProfileSerializer},
		description='Set experience and interests for current user profile.'
	)
	@action(detail=False, methods=['post'], url_path='set-experience', permission_classes=[permissions.IsAuthenticated])
	def set_experience(self, request):
		profile, _ = Profile.objects.get_or_create(user=request.user)
		experience = request.data.get('experience')
		interests = request.data.get('interests')
		if experience is not None:
			profile.experience = experience
		if interests is not None:
			# Stored as comma-separated text; API accepts list or string.
			if isinstance(interests, list):
				profile.interests = ','.join([str(i).strip() for i in interests if str(i).strip()])
			elif isinstance(interests, str):
				profile.interests = interests
			else:
				return Response({'detail': 'interests must be a list of strings or a comma-separated string.'}, status=status.HTTP_400_BAD_REQUEST)
		profile.save(update_fields=['experience', 'interests'])
		return Response(ProfileSerializer(profile, context={'request': request}).data)

	@extend_schema(
		request=ProfileExperienceRequestSerializer,
		responses={200: ProfileSerializer, 400: DetailResponseSerializer},
		description='Update experience and/or interests for current user profile.'
	)
	@action(detail=False, methods=['patch'], url_path='update-experience', permission_classes=[permissions.IsAuthenticated])
	def update_experience(self, request):
		profile, _ = Profile.objects.get_or_create(user=request.user)
		experience = request.data.get('experience')
		interests = request.data.get('interests')

		if experience is None and interests is None:
			return Response({'detail': 'Provide experience and/or interests.'}, status=status.HTTP_400_BAD_REQUEST)

		updated_fields = []
		if experience is not None:
			profile.experience = experience
			updated_fields.append('experience')
		if interests is not None:
			if isinstance(interests, list):
				profile.interests = ','.join([str(i).strip() for i in interests if str(i).strip()])
			elif isinstance(interests, str):
				profile.interests = interests
			else:
				return Response({'detail': 'interests must be a list of strings or a comma-separated string.'}, status=status.HTTP_400_BAD_REQUEST)
			updated_fields.append('interests')

		profile.save(update_fields=updated_fields)
		return Response(ProfileSerializer(profile, context={'request': request}).data)



class AuthViewSet(viewsets.ViewSet):
	permission_classes = [permissions.AllowAny]
	throttle_classes = [ScopedRateThrottle]
	throttle_scope = 'auth'

	def _verify_google_id_token(self, token: str) -> dict:
		client_id = getattr(settings, 'GOOGLE_OAUTH2_CLIENT_ID', '')
		if not client_id:
			raise RuntimeError('GOOGLE_OAUTH2_CLIENT_ID is not configured.')
		return google_id_token.verify_oauth2_token(
			token,
			google_requests.Request(),
			client_id,
		)

	@extend_schema(
		request=LoginRequestSerializer,
		responses={
			200: LoginResponseSerializer,
			400: LoginResponseSerializer,
		},
		description="Login with email and password. Returns user info and token."
	)
	@action(detail=False, methods=['post'])
	def login(self, request):
		"""Login endpoint. Accepts email and password, returns user and token."""
		email = _normalize_email(request.data.get('email'))
		password = request.data.get('password')

		if not email or not password:
			return Response({'detail': 'email and password are required.'}, status=status.HTTP_400_BAD_REQUEST)

		gate = _waitlist_gate_response(email)
		if gate is not None:
			return gate

		user = authenticate(request, email=email, password=password)
		if not user:
			return Response({'detail': 'Invalid credentials.'}, status=status.HTTP_400_BAD_REQUEST)
		_set_last_login(user)
		token = AuthToken.objects.create(user)[1]
		return Response({'user': UserSerializer(user, context={'request': request}).data, 'token': token}, status=status.HTTP_200_OK)

	@extend_schema(
		request=ForgotPasswordRequestOtpSerializer,
		responses={200: DetailResponseSerializer, 400: DetailResponseSerializer, 502: DetailResponseSerializer},
		description='Forgot password: request an OTP sent to the provided email.',
	)
	@action(detail=False, methods=['post'], url_path='forgot-password/request-otp')
	def forgot_password_request_otp(self, request):
		serializer = ForgotPasswordRequestOtpSerializer(data=request.data)
		serializer.is_valid(raise_exception=True)
		email = _normalize_email(serializer.validated_data.get('email'))
		user = User.objects.filter(email__iexact=email).first()
		if not user:
			return Response({'detail': 'No account found for this email.'}, status=status.HTTP_400_BAD_REQUEST)

		min_interval = int(getattr(settings, 'PASSWORD_RESET_OTP_MIN_INTERVAL_SECONDS', 60))
		if min_interval > 0:
			last = PasswordResetOTP.objects.filter(user=user).order_by('-created_at').first()
			if last and last.created_at and (timezone.now() - last.created_at).total_seconds() < min_interval:
				return Response({'detail': 'Please wait before requesting another OTP.'}, status=status.HTTP_400_BAD_REQUEST)

		otp = _generate_password_reset_otp()
		expires_minutes = int(getattr(settings, 'PASSWORD_RESET_OTP_TTL_MINUTES', 10))
		expires_at = timezone.now() + timedelta(minutes=expires_minutes)

		PasswordResetOTP.objects.create(
			user=user,
			otp_hash=make_password(otp),
			otp_expires_at=expires_at,
		)

		subject = 'Your Padlupp password reset code'
		text = (
			f"Your Padlupp password reset code is: {otp}\n\n"
			f"This code expires in {expires_minutes} minutes."
		)
		try:
			send_mailgun_email(to_email=email, subject=subject, text=text, tags=['forgot_password'])
		except EmailSendError:
			return Response({'detail': 'Failed to send OTP email.'}, status=status.HTTP_502_BAD_GATEWAY)
		except Exception:
			return Response({'detail': 'Failed to send OTP email.'}, status=status.HTTP_502_BAD_GATEWAY)

		return Response({'detail': 'OTP sent.'}, status=status.HTTP_200_OK)

	@extend_schema(
		request=ForgotPasswordVerifyOtpSerializer,
		responses={200: ForgotPasswordVerifyOtpResponseSerializer, 400: DetailResponseSerializer},
		description='Forgot password: verify OTP and receive a reset token.',
	)
	@action(detail=False, methods=['post'], url_path='forgot-password/verify-otp')
	def forgot_password_verify_otp(self, request):
		serializer = ForgotPasswordVerifyOtpSerializer(data=request.data)
		serializer.is_valid(raise_exception=True)
		email = _normalize_email(serializer.validated_data.get('email'))
		otp = (serializer.validated_data.get('otp') or '').strip()

		user = User.objects.filter(email__iexact=email).first()
		if not user:
			return Response({'detail': 'No account found for this email.'}, status=status.HTTP_400_BAD_REQUEST)

		now = timezone.now()
		rec = (
			PasswordResetOTP.objects.filter(user=user, otp_used_at__isnull=True)
			.order_by('-created_at')
			.first()
		)
		if not rec or not rec.otp_expires_at or rec.otp_expires_at <= now:
			return Response({'detail': 'OTP expired or invalid.'}, status=status.HTTP_400_BAD_REQUEST)
		if not check_password(otp, rec.otp_hash):
			return Response({'detail': 'OTP expired or invalid.'}, status=status.HTTP_400_BAD_REQUEST)

		reset_token = _generate_password_reset_token()
		reset_token_ttl = int(getattr(settings, 'PASSWORD_RESET_TOKEN_TTL_MINUTES', 30))
		rec.otp_used_at = now
		rec.reset_token_hash = make_password(reset_token)
		rec.reset_token_expires_at = now + timedelta(minutes=reset_token_ttl)
		rec.save(update_fields=['otp_used_at', 'reset_token_hash', 'reset_token_expires_at', 'updated_at'])

		return Response(
			{'detail': 'OTP verified.', 'reset_token': reset_token},
			status=status.HTTP_200_OK,
		)

	@extend_schema(
		request=ForgotPasswordResetPasswordSerializer,
		responses={200: DetailResponseSerializer, 400: DetailResponseSerializer},
		description='Forgot password: reset password using the reset token from OTP verification.',
	)
	@action(detail=False, methods=['post'], url_path='forgot-password/reset-password')
	def forgot_password_reset_password(self, request):
		serializer = ForgotPasswordResetPasswordSerializer(data=request.data)
		serializer.is_valid(raise_exception=True)
		reset_token = (serializer.validated_data.get('reset_token') or '').strip()
		new_password = serializer.validated_data.get('new_password')

		now = timezone.now()
		# Search recent candidates only for performance.
		candidates = PasswordResetOTP.objects.filter(
			reset_token_used_at__isnull=True,
			reset_token_expires_at__gt=now,
		).select_related('user').order_by('-created_at')[:25]

		match = None
		for rec in candidates:
			if rec.reset_token_hash and check_password(reset_token, rec.reset_token_hash):
				match = rec
				break

		if not match:
			return Response({'detail': 'Reset token expired or invalid.'}, status=status.HTTP_400_BAD_REQUEST)

		user = match.user
		user.set_password(new_password)
		user.save(update_fields=['password', 'updated_at'])
		AuthToken.objects.filter(user=user).delete()
		match.reset_token_used_at = now
		match.save(update_fields=['reset_token_used_at', 'updated_at'])

		return Response({'detail': 'Password reset successful.'}, status=status.HTTP_200_OK)

	@extend_schema(
		request=InviteUserRequestSerializer,
		responses={
			200: InviteUserResponseSerializer,
			400: DetailResponseSerializer,
			401: DetailResponseSerializer,
			502: DetailResponseSerializer,
		},
		description=(
			"Invite someone to Padlupp by email. Sends an invite email with the signup link and "
			"adds the invitee to the waitlist so they can sign up during the beta."
		),
	)
	@action(detail=False, methods=['post'], url_path='invite', permission_classes=[permissions.IsAuthenticated])
	def invite(self, request):
		serializer = InviteUserRequestSerializer(data=request.data)
		serializer.is_valid(raise_exception=True)
		data = serializer.validated_data

		email = _normalize_email(data.get('email'))
		name = (data.get('name') or '').strip()
		if not email:
			return Response({'detail': 'email is required.'}, status=status.HTTP_400_BAD_REQUEST)

		# Don't invite existing users.
		if User.objects.filter(email__iexact=email).exists():
			return Response({'detail': 'That email already belongs to an existing user.'}, status=status.HTTP_400_BAD_REQUEST)

		# Add to waitlist (so beta gating allows signup).
		waitlister, created = Waitlister.objects.get_or_create(
			email=email,
			defaults={'name': name},
		)
		if not created and name and not (waitlister.name or '').strip():
			waitlister.name = name
			waitlister.save(update_fields=['name', 'updated_at'])

		inviter_name = (getattr(request.user, 'name', '') or '').strip() or 'Someone'
		platform_url = 'https://app.padlupp.com/'
		subject = "You're invited to Padlupp"
		text = (
			f"Hello {name}\n\n"
			f"{inviter_name} invited you to join Padlupp - they thought you’d benefit from having an accountability partner.\n\n"
			"Ready to join them?\n"
			f"{platform_url}\n\n"
			"Thanks,\n"
			"The Padlupp Team"
		)

		try:
			send_mailgun_email(
				to_email=email,
				subject=subject,
				text=text,
				tags=['invite'],
			)
		except EmailSendError:
			pass
			# return Response({'detail': 'Failed to send invite email.'}, status=status.HTTP_502_BAD_GATEWAY)
		except Exception:
			pass
			# return Response({'detail': 'Failed to send invite email.'}, status=status.HTTP_502_BAD_GATEWAY)

		return Response(
			{
				'detail': 'Invite sent.',
				'waitlisted': True,
			},
			status=status.HTTP_200_OK,
		)

	@extend_schema(
		responses={200: ProfileSerializer},
		description='Get current user profile.'
	)
	@action(detail=False, methods=['get'], url_path='userprofile', permission_classes=[permissions.IsAuthenticated])
	def userprofile(self, request):
		profile, _ = Profile.objects.get_or_create(user=request.user)
		return Response(ProfileSerializer(profile, context={'request': request}).data)

	@extend_schema(
		request=UserUpdateRequestSerializer,
		responses={
			200: UserSerializer,
			400: DetailResponseSerializer,
		},
		description='Patch update the current user.'
	)
	@action(detail=False, methods=['patch'], url_path='user', permission_classes=[permissions.IsAuthenticated])
	def user(self, request):
		serializer = UserUpdateRequestSerializer(data=request.data)
		serializer.is_valid(raise_exception=True)
		data = serializer.validated_data
		user = request.user

		updated_fields = []
		if 'name' in data:
			user.name = data.get('name')
			updated_fields.append('name')
		if 'phone' in data:
			phone = (data.get('phone') or '').strip()
			user.phone = phone or None
			updated_fields.append('phone')
		if 'preferred_notification_email' in data:
			val = (data.get('preferred_notification_email') or '').strip()
			user.preferred_notification_email = val or None
			updated_fields.append('preferred_notification_email')
		if 'preferred_notification_phone' in data:
			val = (data.get('preferred_notification_phone') or '').strip()
			user.preferred_notification_phone = val or None
			updated_fields.append('preferred_notification_phone')

		if not updated_fields:
			return Response({'detail': 'No fields provided.'}, status=status.HTTP_400_BAD_REQUEST)

		# Keep timestamps consistent with the rest of the codebase.
		updated_fields.append('updated_at')
		try:
			user.save(update_fields=updated_fields)
		except IntegrityError:
			# Most likely: duplicate phone (unique constraint)
			return Response({'detail': 'Phone already in use.'}, status=status.HTTP_400_BAD_REQUEST)

		return Response(UserSerializer(user, context={'request': request}).data)

	@extend_schema(
		request=GoogleAuthRequestSerializer,
		responses={
			200: GoogleAuthResponseSerializer,
			400: DetailResponseSerializer,
			500: DetailResponseSerializer,
		},
		description=(
			"Google sign-in. Verifies a Google `id_token`, logs the user in, and returns a Knox token. "
			"Fails if the user does not already exist."
		),
	)
	@action(detail=False, methods=['post'], url_path='google-signin')
	def google_signin(self, request):
		id_token_str = request.data.get('id_token')
		if not id_token_str:
			return Response({'detail': 'id_token is required.'}, status=status.HTTP_400_BAD_REQUEST)

		try:
			payload = self._verify_google_id_token(id_token_str)
		except RuntimeError as exc:
			return Response({'detail': str(exc)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
		except ValueError:
			return Response({'detail': 'Invalid Google token.'}, status=status.HTTP_400_BAD_REQUEST)

		email = _normalize_email(payload.get('email'))
		if not email:
			return Response({'detail': 'Google token missing email.'}, status=status.HTTP_400_BAD_REQUEST)

		gate = _waitlist_gate_response(email)
		if gate is not None:
			return gate

		user = User.objects.filter(email=email).first()
		if not user:
			return Response({'detail': 'No account found for this email.'}, status=status.HTTP_400_BAD_REQUEST)

		# mark verified if Google confirms it
		if payload.get('email_verified') and not user.email_verified:
			user.email_verified = True
			user.save(update_fields=['email_verified'])
		_set_last_login(user)
		token = AuthToken.objects.create(user)[1]
		return Response({'user': UserSerializer(user, context={'request': request}).data, 'token': token}, status=status.HTTP_200_OK)

	@extend_schema(
		request=GoogleAuthRequestSerializer,
		responses={
			201: GoogleAuthResponseSerializer,
			400: DetailResponseSerializer,
			500: DetailResponseSerializer,
		},
		description=(
			"Google sign-up. Verifies a Google `id_token`, creates a user if the email is unused, "
			"creates a Profile, and returns a Knox token."
		),
	)
	@action(detail=False, methods=['post'], url_path='google-signup')
	def google_signup(self, request):
		id_token_str = request.data.get('id_token')
		if not id_token_str:
			return Response({'detail': 'id_token is required.'}, status=status.HTTP_400_BAD_REQUEST)

		try:
			payload = self._verify_google_id_token(id_token_str)
		except RuntimeError as exc:
			return Response({'detail': str(exc)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
		except ValueError:
			return Response({'detail': 'Invalid Google token.'}, status=status.HTTP_400_BAD_REQUEST)

		email = _normalize_email(payload.get('email'))
		if not email:
			return Response({'detail': 'Google token missing email.'}, status=status.HTTP_400_BAD_REQUEST)

		gate = _waitlist_gate_response(email)
		if gate is not None:
			return gate

		if User.objects.filter(email=email).exists():
			return Response({'detail': 'Email already in use.'}, status=status.HTTP_400_BAD_REQUEST)

		name = (payload.get('name') or '').strip()
		if not name:
			name = (request.data.get('name') or '').strip()
		if not name:
			# last resort fallback
			name = email.split('@')[0]

		phone = (request.data.get('phone') or '').strip() or None

		user = User(email=email, name=name, phone=phone)
		user.set_unusable_password()
		if payload.get('email_verified'):
			user.email_verified = True
		user.save()
		Profile.objects.get_or_create(user=user)
		_set_last_login(user)
		token = AuthToken.objects.create(user)[1]
		return Response({'user': UserSerializer(user, context={'request': request}).data, 'token': token}, status=status.HTTP_201_CREATED)

	@extend_schema(
		request=GoogleAuthRequestSerializer,
		responses={
			200: GoogleAuthResponseSerializer,
			201: GoogleAuthResponseSerializer,
			400: DetailResponseSerializer,
			500: DetailResponseSerializer,
		},
		description=(
			"Google auth (signup-or-signin). Verifies a Google `id_token`. "
			"If the user exists, returns 200 with a Knox token. Otherwise creates the user + Profile and returns 201."
		),
	)
	@action(detail=False, methods=['post'], url_path='google-auth')
	def google_auth(self, request):
		id_token_str = request.data.get('id_token')
		if not id_token_str:
			return Response({'detail': 'id_token is required.'}, status=status.HTTP_400_BAD_REQUEST)

		try:
			payload = self._verify_google_id_token(id_token_str)
		except RuntimeError as exc:
			return Response({'detail': str(exc)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
		except ValueError:
			return Response({'detail': 'Invalid Google token.'}, status=status.HTTP_400_BAD_REQUEST)

		email = _normalize_email(payload.get('email'))
		if not email:
			return Response({'detail': 'Google token missing email.'}, status=status.HTTP_400_BAD_REQUEST)

		gate = _waitlist_gate_response(email)
		if gate is not None:
			return gate

		user = User.objects.filter(email=email).first()
		created = False
		if not user:
			name = (payload.get('name') or '').strip()
			if not name:
				name = (request.data.get('name') or '').strip()
			if not name:
				name = email.split('@')[0]

			phone = (request.data.get('phone') or '').strip() or None
			user = User(email=email, name=name, phone=phone)
			user.set_unusable_password()
			if payload.get('email_verified'):
				user.email_verified = True
			user.save()
			Profile.objects.get_or_create(user=user)
			created = True
		else:
			if payload.get('email_verified') and not user.email_verified:
				user.email_verified = True
				user.save(update_fields=['email_verified'])
		_set_last_login(user)
		token = AuthToken.objects.create(user)[1]
		resp_status = status.HTTP_201_CREATED if created else status.HTTP_200_OK
		return Response({'user': UserSerializer(user, context={'request': request}).data, 'token': token}, status=resp_status)


	# notification preferences
	@extend_schema(
		request=NotificationPreferencesSerializer,
		responses={
			200: NotificationPreferencesSerializer,
			400: DetailResponseSerializer,
		},
		description='Update notification preferences for the current user. Allows partial updates.'
	)
	@action(detail=False, methods=['patch'], url_path='notification-preferences', permission_classes=[permissions.IsAuthenticated])
	def notification_preferences(self, request):
		user = request.user
		serializer = NotificationPreferencesSerializer(user, data=request.data, partial=True)
		if serializer.is_valid():
			serializer.save()
			return Response(serializer.data, status=status.HTTP_200_OK)
		return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

	@extend_schema(
		request=DeleteAccountRequestSerializer,
		responses={
			201: DetailResponseSerializer,
			400: DetailResponseSerializer,
		},
		description='Receive an account deletion request for the current user.',
	)
	@action(
		detail=False,
		methods=['post'],
		url_path='delete-account',
		permission_classes=[permissions.IsAuthenticated],
	)
	def delete_account(self, request):
		serializer = DeleteAccountRequestSerializer(data=request.data)
		serializer.is_valid(raise_exception=True)
		reason = (serializer.validated_data.get('reason') or '').strip()
		if not reason:
			return Response({'detail': 'reason is required.'}, status=status.HTTP_400_BAD_REQUEST)

		AccountDeletionRequest.objects.create(user=request.user, reason=reason)
		# temporarily deactivate the account immediately to prevent further use while we process the deletion request
		request.user.is_active = False
		request.user.save(update_fields=['is_active'])
		AuthToken.objects.filter(user=request.user).delete()
		return Response({'detail': 'Deletion request received.'}, status=status.HTTP_201_CREATED)



class GoalViewSet(viewsets.ModelViewSet):
	serializer_class = GoalSerializer
	permission_classes = [permissions.IsAuthenticated]
	search_fields = ['title', 'description', 'category']
	ordering_fields = ['title', 'created_at', 'target_date']
	ordering = ['-created_at']

	def get_queryset(self):
		user = self.request.user
		# Get goals the user owns, participates in, or has joined as a member.
		return (
			Goal.objects.filter(
			models.Q(user=user) |
			models.Q(members=user) |
			models.Q(partnership__user_a=user) |
			models.Q(partnership__user_b=user)
			)
			.distinct()
		)


	def perform_create(self, serializer):
		conversation = serializer.validated_data.pop('conversation', None)
		partnership = None
		if conversation:
			if not _user_is_member_of_conversation(self.request.user.id, conversation):
				raise PermissionDenied('You are not a member of this conversation.')
			partnership = getattr(conversation, 'partnership', None)
		profile, _ = Profile.objects.get_or_create(user=self.request.user)
		if not profile_is_complete(profile):
			raise ValidationError({
				'profile': 'Complete onboarding by adding your experience and at least one interest before creating a goal.',
			})
		goal = serializer.save(user=self.request.user, partnership=partnership)
		_add_goal_member(goal, self.request.user, self.request.user)
		if partnership:
			_add_goal_member(goal, partnership.user_a, self.request.user)
			_add_goal_member(goal, partnership.user_b, self.request.user)
		goal.refresh_from_db()
		if goal.is_public:
			_ensure_goal_conversation(goal, self.request.user)

	def perform_update(self, serializer):
		# Every active goal member may collaborate on goal details.
		goal = self.get_object()
		user = self.request.user
		if user.id in _goal_member_ids(goal):
			requested_visibility = serializer.validated_data.get('is_public', goal.is_public)
			if goal.user_id != user.id and requested_visibility != goal.is_public:
				raise PermissionDenied('Only the goal owner can change sharing visibility.')
			goal = serializer.save()
			if goal.partnership:
				_add_goal_member(goal, goal.partnership.user_a, user)
				_add_goal_member(goal, goal.partnership.user_b, user)
		else:
			raise PermissionDenied("You do not have permission to update this goal.")

	def perform_destroy(self, instance):
		if instance.user_id != self.request.user.id:
			raise PermissionDenied('Only the goal owner can delete this goal.')
		instance.delete()

	@extend_schema(
		responses={200: PublicGoalPreviewSerializer, 403: DetailResponseSerializer, 404: DetailResponseSerializer},
		description='Public, privacy-limited preview of a shared goal.',
	)
	@action(detail=True, methods=['get'], url_path='public-preview', permission_classes=[permissions.AllowAny])
	def public_preview(self, request, pk=None):
		share_serializer = GoalJoinRequestSerializer(data={'shared_id': request.query_params.get('shared_id')})
		if not share_serializer.is_valid():
			return Response({'detail': 'Goal not found or the share link is invalid.'}, status=status.HTTP_404_NOT_FOUND)
		shared_id = share_serializer.validated_data['shared_id']
		goal = Goal.objects.select_related('user').filter(pk=pk, is_public=True, shared_id=shared_id).first()
		if not goal:
			return Response({'detail': 'Goal not found or the share link is invalid.'}, status=status.HTTP_404_NOT_FOUND)
		return Response(PublicGoalPreviewSerializer(goal, context={'request': request}).data)

	@extend_schema(
		request=GoalJoinRequestSerializer,
		responses={200: GoalJoinResponseSerializer, 400: DetailResponseSerializer, 403: DetailResponseSerializer, 404: DetailResponseSerializer},
		description='Join a public goal using its shared_id.'
	)
	@action(detail=False, methods=['post'], url_path='join-goal')
	def join_goal(self, request):
		serializer = GoalJoinRequestSerializer(data=request.data)
		serializer.is_valid(raise_exception=True)
		shared_id = serializer.validated_data['shared_id']
		goal = Goal.objects.filter(shared_id=shared_id).select_related('user', 'partnership').first()
		if not goal:
			return Response({'detail': 'Goal not found.'}, status=status.HTTP_404_NOT_FOUND)
		if not goal.is_public:
			return Response({'detail': 'This goal is not public.'}, status=status.HTTP_403_FORBIDDEN)

		created = _add_goal_member(goal, request.user, request.user)
		goal.is_shared = True
		goal.save(update_fields=['is_shared', 'updated_at'])
		_ensure_goal_conversation(goal, request.user)

		# Notify the goal owner (best-effort). Only send if this request actually
		# created a new membership row to avoid duplicate emails.
		if created and _email_notifications_enabled():
			owner = getattr(goal, 'user', None)
			joiner = request.user
			if owner and owner.email and owner.id != joiner.id and owner.notify_on_new_match:
				joiner_name = (getattr(joiner, 'name', '') or getattr(joiner, 'email', '') or 'Someone').strip()
				owner_name = (getattr(owner, 'name', '') or 'there').strip()
				goal_title = (getattr(goal, 'title', '') or 'your goal').strip()
				goal_url = _goal_direct_link(goal.id)
				subject = f"{joiner_name} just joined your goal — let’s go!"
				text = (
					f"Hi {owner_name},\n\n"
					f"Good news: {joiner_name} just joined your goal \"{goal_title}\" on Padlupp.\n\n"
					"This is your moment to set the tone — a quick welcome message can make it way more fun (and way more likely they stick with it).\n\n"
					f"Jump into the goal: {goal_url}\n\n"
					f"Jump into the conversation and say hi! The more you engage with your accountability partner, the more likely you both are to achieve your goals.\nhttps://app.padlupp.com/messages"
				)
				try:
					send_mailgun_email(
						to_email=owner.email,
						subject=subject,
						text=text,
						tags=['goal_join'],
					)
				except EmailSendError:
					pass
		return Response(
			{
				'detail': 'Joined goal.',
				'goal_id': goal.id,
				'direct_link': _goal_direct_link(goal.id),
			},
			status=status.HTTP_200_OK,
		)

	@extend_schema(
		request=GoalShareRequestSerializer,
		responses={200: GoalShareResponseSerializer, 400: DetailResponseSerializer, 403: DetailResponseSerializer},
		description='Share a goal with existing users and invite new users by email.'
	)
	@action(detail=True, methods=['post'], url_path='share')
	def share(self, request, pk=None):
		goal = self.get_object()
		if goal.user_id != request.user.id:
			return Response({'detail': 'You do not have permission to share this goal.'}, status=status.HTTP_403_FORBIDDEN)

		serializer = GoalShareRequestSerializer(data=request.data)
		serializer.is_valid(raise_exception=True)
		emails = list(dict.fromkeys([email.strip().lower() for email in serializer.validated_data['emails'] if email.strip()]))
		message = (serializer.validated_data.get('message') or '').strip()
		added_user_ids: list[int] = []
		invited_emails: list[str] = []
		if not goal.is_public:
			goal.is_public = True
			goal.save(update_fields=['is_public', 'shared_id', 'invite_link', 'updated_at'])
		goal_url = goal.invite_link
		_ensure_goal_conversation(goal, request.user)
		inviter_name = (getattr(request.user, 'name', '') or getattr(request.user, 'email', '') or 'Someone').strip()

		for email in emails:
			if email == (request.user.email or '').strip().lower():
				continue
			user = User.objects.filter(email__iexact=email, deleted=False).first()
			if user:
				created = _add_goal_member(goal, user, request.user)
				if created:
					added_user_ids.append(user.id)
					if user.notify_on_new_match:
						Notification.objects.create(
							user=user,
							type='goal_shared',
							payload={
							'goal_id': goal.id,
							'goal_title': goal.title,
							'from_user_id': request.user.id,
							'from_user_name': inviter_name,
							'link': goal_url,
							'message': message,
							},
						)
					subject = f'{inviter_name} added you to a goal on Padlupp'
					text = (
						f'Hi {getattr(user, "name", "there") or "there"},\n\n'
						f'{inviter_name} added you to "{goal.title}" on Padlupp.\n\n'
					)
					if message:
						text += f'Message: {message}\n\n'
					text += f'Open the goal: {goal_url}\n'
					try:
						if user.notify_on_new_match and _email_notifications_enabled():
							send_mailgun_email(
								to_email=user.email,
								subject=subject,
								text=text,
								tags=['goal_share', 'existing_user'],
							)
					except EmailSendError:
						pass
				continue

			invited_emails.append(email)
			Waitlister.objects.get_or_create(email=email, defaults={'name': ''})
			subject = f'You were invited to Padlupp by {inviter_name}'
			text = (
				f'Hi there,\n\n{inviter_name} invited you to Padlupp and shared "{goal.title}" with you.\n\n'
			)
			if message:
				text += f'Message: {message}\n\n'
			text += f'Join Padlupp to view the goal: {goal_url}\n'
			try:
				if _email_notifications_enabled():
					send_mailgun_email(
						to_email=email,
						subject=subject,
						text=text,
						tags=['goal_share', 'invite'],
					)
			except EmailSendError:
				pass

		goal.is_shared = True
		goal.save(update_fields=['is_shared', 'updated_at'])
		return Response(
			{
				'detail': 'Goal shared.',
				'goal_id': goal.id,
				'direct_link': goal_url,
				'public_share_link': goal_url,
				'share_link': goal_url,
				'invite_link': goal_url,
				'added_user_ids': added_user_ids,
				'invited_emails': invited_emails,
			},
			status=status.HTTP_200_OK,
		)

	@extend_schema(
		responses={200: PublicUserSerializer(many=True), 403: DetailResponseSerializer, 404: DetailResponseSerializer},
		description='Return the list of all members in this goal. Only goal members can access this endpoint.',
	)
	@action(detail=True, methods=['get'], url_path='members')
	def members(self, request, pk=None):
		goal = self.get_object()
		allowed_ids = set(_goal_member_ids(goal))
		if request.user.id not in allowed_ids:
			return Response({'detail': 'You are not a member of this goal.'}, status=status.HTTP_403_FORBIDDEN)

		# Preserve stable ordering (owner/partners first if present in _goal_member_ids).
		ordered_ids = _goal_member_ids(goal)
		users = list(User.objects.filter(id__in=ordered_ids, deleted=False))
		user_by_id = {u.id: u for u in users}
		ordered_users = [user_by_id[uid] for uid in ordered_ids if uid in user_by_id]
		return Response(PublicUserSerializer(ordered_users, many=True, context={'request': request}).data, status=status.HTTP_200_OK)

	@extend_schema(
		parameters=[
			OpenApiParameter(
				name='user_id',
				type=OpenApiTypes.INT,
				location=OpenApiParameter.PATH,
				required=True,
				description='User id of the member to remove from this goal.',
			),
		],
		responses={200: DetailResponseSerializer, 400: DetailResponseSerializer, 403: DetailResponseSerializer, 404: DetailResponseSerializer},
		description='Remove a member from this goal. Only the goal owner can remove members.',
	)
	@action(detail=True, methods=['delete'], url_path=r'members/(?P<user_id>\d+)')
	def remove_member(self, request, pk=None, user_id=None):
		goal = self.get_object()
		if goal.user_id != request.user.id:
			return Response({'detail': 'Only the goal owner can remove members.'}, status=status.HTTP_403_FORBIDDEN)

		try:
			member_id = int(user_id)
		except (TypeError, ValueError):
			return Response({'detail': 'Invalid user_id.'}, status=status.HTTP_400_BAD_REQUEST)

		if member_id == goal.user_id:
			return Response({'detail': 'The goal owner cannot be removed.'}, status=status.HTTP_400_BAD_REQUEST)
		if goal.partnership_id and member_id in [getattr(goal.partnership, 'user_a_id', None), getattr(goal.partnership, 'user_b_id', None)]:
			return Response({'detail': 'Partnership members cannot be removed from a partnership goal.'}, status=status.HTTP_400_BAD_REQUEST)

		with transaction.atomic():
			deleted_count, _ = GoalMembership.objects.filter(goal=goal, user_id=member_id).delete()
			if deleted_count == 0:
				return Response({'detail': 'User is not a member of this goal.'}, status=status.HTTP_404_NOT_FOUND)

			conversation = Conversation.objects.filter(goal=goal).first()
			if conversation:
				ConversationMembership.objects.filter(conversation=conversation, user_id=member_id).delete()

		return Response({'detail': 'Member removed.'}, status=status.HTTP_200_OK)


class PartnershipViewSet(viewsets.ReadOnlyModelViewSet):
	serializer_class = PartnershipSerializer
	permission_classes = [permissions.IsAuthenticated]

	def get_queryset(self):
		user = self.request.user
		return Partnership.objects.filter(models.Q(user_a=user) | models.Q(user_b=user)).order_by('-created_at')


class MatchViewSet(viewsets.ModelViewSet):
	serializer_class = MatchSerializer
	permission_classes = [permissions.IsAuthenticated]

	def get_queryset(self):
		# Only show matches initiated by the current user
		return Match.objects.filter(from_user=self.request.user).order_by('-created_at')

	@extend_schema(
		responses={200: ProfileSerializer(many=True)},
		description='Discover profiles not swiped or partnered yet.'
	)
	@action(detail=False, methods=['get'])
	def discover(self, request):
		user = request.user
		source_profile, _ = Profile.objects.get_or_create(user=user)

		# Reconsider old swipes after a cooldown, but never suggest an existing buddy.
		swiped_user_ids = Match.objects.filter(
			from_user=user,
			created_at__gte=timezone.now() - timedelta(days=30),
		).values_list('to_user_id', flat=True)
		partner_user_ids = Partnership.objects.filter(
			models.Q(user_a=user) | models.Q(user_b=user)
		).values_list('user_a_id', 'user_b_id')
		partner_user_ids_flat = {uid for pair in partner_user_ids for uid in pair}

		excluded_ids = set(swiped_user_ids) | partner_user_ids_flat | {user.id}

		profiles = list(
			Profile.objects.select_related('user')
			.filter(user__is_active=True, user__deleted=False)
			.exclude(user_id__in=excluded_ids)
		)
		profiles.sort(
			key=lambda candidate: (
				-compatibility_details(source_profile, candidate)['score'],
				-candidate.created_at.timestamp(),
				candidate.user_id,
			)
		)

		page = self.paginate_queryset(profiles)
		serializer = ProfileSerializer(
			page if page is not None else profiles,
			many=True,
			context={'request': request, 'source_profile': source_profile},
		)
		if page is not None:
			return self.get_paginated_response(serializer.data)
		return Response(serializer.data)

	def perform_create(self, serializer):
		from_user = self.request.user
		to_user = serializer.validated_data['to_user']
		action = serializer.validated_data['action']

		# Save the current user's action
		match = serializer.save(from_user=from_user)

		# If user liked someone, check for mutual like
		if action == Match.LIKE:
			mutual_like = Match.objects.filter(
				from_user=to_user,
				to_user=from_user,
				action=Match.LIKE,
			).exists()
			if mutual_like:
				# Ensure we don't create duplicate partnerships
				user_a, user_b = sorted([from_user, to_user], key=lambda u: u.id)
				partnership, created = Partnership.objects.get_or_create(user_a=user_a, user_b=user_b)
				if created:
					# Auto-create conversation for this partnership
					Conversation.objects.create(partnership=partnership)
					if user_a.notify_on_new_match:
						Notification.objects.create(
							user=user_a,
							type='new_match',
							payload={'partner_id': user_b.id, 'partnership_id': partnership.id},
						)
					if user_b.notify_on_new_match:
						Notification.objects.create(
							user=user_b,
							type='new_match',
							payload={'partner_id': user_a.id, 'partnership_id': partnership.id},
						)

		return match


class TaskViewSet(viewsets.ModelViewSet):
	serializer_class = TaskSerializer
	permission_classes = [permissions.IsAuthenticated]

	def get_queryset(self):
		user = self.request.user
		return (
			Task.objects.filter(
				models.Q(owner=user)
				| models.Q(partnership__user_a=user)
				| models.Q(partnership__user_b=user)
				| models.Q(goal__user=user)
				| models.Q(goal__members=user)
				| models.Q(goal__partnership__user_a=user)
				| models.Q(goal__partnership__user_b=user)
			)
			.distinct()
			.order_by('-created_at')
		)

	def _assert_task_owner(self, task: Task):
		if task.owner_id != self.request.user.id:
			raise PermissionDenied('Only the task owner can modify this task.')

	def perform_create(self, serializer):
		user = self.request.user
		goal = serializer.validated_data.get('goal')
		partnership = serializer.validated_data.get('partnership')

		# Validate that the user can create a task for this goal.
		goal_partnership = getattr(goal, 'partnership', None)
		in_goal_partnership = bool(
			goal_partnership
			and user.id in [goal_partnership.user_a_id, goal_partnership.user_b_id]
		)
		if user.id not in _goal_member_ids(goal) and not in_goal_partnership:
			raise ValidationError({'goal': 'You do not have access to this goal.'})

		# Validate any explicit partnership, and default to goal.partnership when present.
		if partnership and user.id not in [partnership.user_a_id, partnership.user_b_id]:
			raise ValidationError({'partnership': 'You are not a member of this partnership.'})
		if partnership and goal_partnership and partnership.id != goal_partnership.id:
			raise ValidationError({'partnership': 'Partnership must match the goal partnership.'})
		effective_partnership = partnership or goal_partnership

		task = serializer.save(owner=user, partnership=effective_partnership)
		# Notify partner (if any) about new task
		if task.partnership:
			partner = task.partnership.user_a if task.partnership.user_b == user else task.partnership.user_b
			if partner.notify_on_reminders:
				Notification.objects.create(
					user=partner,
					type='new_task',
					payload={'task_id': task.id, 'title': task.title},
				)

	def perform_update(self, serializer):
		self._assert_task_owner(serializer.instance)
		serializer.save()

	def perform_destroy(self, instance):
		self._assert_task_owner(instance)
		instance.delete()

	@extend_schema(
		responses={201: TimerSessionSerializer},
		description='Start a timer session for a task.'
	)
	@action(detail=True, methods=['post'])
	def start_timer(self, request, pk=None):
		task = self.get_object()
		self._assert_task_owner(task)
		# End any existing open timer session for this user on this task
		TimerSession.objects.filter(task=task, user=request.user, ended_at__isnull=True).update(ended_at=timezone.now())
		session = TimerSession.objects.create(task=task, user=request.user, started_at=models.functions.Now())
		if task.status == Task.STATUS_PLANNED:
			task.status = Task.STATUS_IN_PROGRESS
			task.save(update_fields=['status', 'updated_at'])
		return Response(TimerSessionSerializer(session).data, status=status.HTTP_201_CREATED)

	@extend_schema(
		responses={200: TimerSessionSerializer, 400: DetailResponseSerializer},
		description='Stop the active timer session for a task.'
	)
	@action(detail=True, methods=['post'])
	def stop_timer(self, request, pk=None):
		task = self.get_object()
		self._assert_task_owner(task)
		session = TimerSession.objects.filter(task=task, user=request.user, ended_at__isnull=True).order_by('-started_at').first()
		if not session:
			return Response({'detail': 'No active timer session.'}, status=status.HTTP_400_BAD_REQUEST)
		session.ended_at = models.functions.Now()
		session.save(update_fields=['ended_at', 'updated_at'])
		return Response(TimerSessionSerializer(session).data)

	@extend_schema(
		responses={200: TaskSerializer, 400: DetailResponseSerializer},
		description='Request review for a task.'
	)
	@action(detail=True, methods=['post'])
	def request_review(self, request, pk=None):
		task = self.get_object()
		self._assert_task_owner(task)
		if task.status not in [Task.STATUS_IN_PROGRESS, Task.STATUS_NEEDS_REVISION]:
			return Response({'detail': 'Task must be in progress or needs revision to request review.'}, status=status.HTTP_400_BAD_REQUEST)
		task.status = Task.STATUS_PENDING_REVIEW
		task.save(update_fields=['status', 'updated_at'])
		# Notify partner that review is requested
		if task.partnership:
			partner = task.partnership.user_a if task.partnership.user_b == request.user else task.partnership.user_b
			if partner.notify_on_reminders:
				Notification.objects.create(
					user=partner,
					type='review_requested',
					payload={'task_id': task.id, 'title': task.title},
				)
		return Response(TaskSerializer(task).data)

	@extend_schema(
		responses={200: TaskSerializer},
		description='Mark task as not completed.'
	)
	@action(detail=True, methods=['post'])
	def mark_not_completed(self, request, pk=None):
		task = self.get_object()
		self._assert_task_owner(task)
		task.status = Task.STATUS_NOT_COMPLETED
		task.save(update_fields=['status', 'updated_at'])
		return Response(TaskSerializer(task).data)

	@extend_schema(
		responses={200: TaskSerializer, 400: DetailResponseSerializer, 403: DetailResponseSerializer},
		description='Approve a task as partner.'
	)
	@action(detail=True, methods=['post'])
	def approve(self, request, pk=None):
		task = self.get_object()
		# Only partner (not owner) can approve
		if not task.partnership:
			return Response({'detail': 'Task is not linked to a partnership.'}, status=status.HTTP_400_BAD_REQUEST)
		if request.user not in [task.partnership.user_a, task.partnership.user_b] or request.user == task.owner:
			return Response({'detail': 'Only the partner can approve this task.'}, status=status.HTTP_403_FORBIDDEN)
		if task.status != Task.STATUS_PENDING_REVIEW:
			return Response({'detail': 'Task must be pending review to approve.'}, status=status.HTTP_400_BAD_REQUEST)

		# Update task status
		task.status = Task.STATUS_COMPLETED
		task.save(update_fields=['status', 'updated_at'])

		# Update latest evidence (if any)
		evidence = task.evidences.order_by('-submitted_at').first()
		if evidence:
			evidence.approved = True
			evidence.reviewer = request.user
			evidence.reviewed_at = models.functions.Now()
			evidence.save(update_fields=['approved', 'reviewer', 'reviewed_at'])

		# Notify task owner
		if task.owner.notify_on_reminders:
			Notification.objects.create(
				user=task.owner,
				type='task_approved',
				payload={'task_id': task.id},
			)
		return Response(TaskSerializer(task).data)

	@extend_schema(
		request=TaskRequestChangesRequestSerializer,
		responses={200: TaskSerializer, 400: DetailResponseSerializer, 403: DetailResponseSerializer},
		description='Request changes for a task with optional comment.'
	)
	@action(detail=True, methods=['post'])
	def request_changes(self, request, pk=None):
		task = self.get_object()
		if not task.partnership:
			return Response({'detail': 'Task is not linked to a partnership.'}, status=status.HTTP_400_BAD_REQUEST)
		if request.user not in [task.partnership.user_a, task.partnership.user_b] or request.user == task.owner:
			return Response({'detail': 'Only the partner can request changes.'}, status=status.HTTP_403_FORBIDDEN)
		if task.status != Task.STATUS_PENDING_REVIEW:
			return Response({'detail': 'Task must be pending review to request changes.'}, status=status.HTTP_400_BAD_REQUEST)

		comment = request.data.get('comment', '')

		# Update task status
		task.status = Task.STATUS_NEEDS_REVISION
		task.save(update_fields=['status', 'updated_at'])

		# Update latest evidence (if any)
		evidence = task.evidences.order_by('-submitted_at').first()
		if evidence:
			evidence.approved = False
			evidence.reviewer = request.user
			evidence.reviewed_at = models.functions.Now()
			evidence.save(update_fields=['approved', 'reviewer', 'reviewed_at'])

		# Notify task owner with comment in payload
		if task.owner.notify_on_reminders:
			Notification.objects.create(
				user=task.owner,
				type='task_changes_requested',
				payload={'task_id': task.id, 'comment': comment},
			)
		return Response(TaskSerializer(task).data)


class SubTaskViewSet(viewsets.ModelViewSet):
	serializer_class = SubTaskSerializer
	permission_classes = [permissions.IsAuthenticated]

	def get_queryset(self):
		return SubTask.objects.filter(owner=self.request.user).order_by('-created_at')

	def perform_create(self, serializer):
		task = serializer.validated_data['task']
		if task.owner_id != self.request.user.id:
			raise PermissionDenied('Only the task owner can create subtasks.')
		serializer.save(owner=self.request.user)


class TimerSessionViewSet(viewsets.ReadOnlyModelViewSet):
	serializer_class = TimerSessionSerializer
	permission_classes = [permissions.IsAuthenticated]

	def get_queryset(self):
		return TimerSession.objects.filter(user=self.request.user).order_by('-created_at')


class EvidenceViewSet(viewsets.ModelViewSet):
	serializer_class = EvidenceSerializer
	permission_classes = [permissions.IsAuthenticated]

	def get_queryset(self):
		return Evidence.objects.filter(submitted_by=self.request.user).order_by('-created_at')

	def perform_create(self, serializer):
		task = serializer.validated_data['task']
		subtask = serializer.validated_data.get('subtask')
		if task.owner_id != self.request.user.id:
			raise PermissionDenied('Only the task owner can submit evidence.')
		if subtask and subtask.task_id != task.id:
			raise ValidationError({'subtask': 'Subtask must belong to the selected task.'})
		evidence = serializer.save(submitted_by=self.request.user)
		# Notify partner that evidence was submitted
		task = evidence.task
		if task.partnership:
			partner = task.partnership.user_a if task.partnership.user_b == self.request.user else task.partnership.user_b
			if partner.notify_on_reminders:
				Notification.objects.create(
					user=partner,
					type='evidence_submitted',
					payload={'task_id': task.id, 'evidence_id': evidence.id},
				)


class ConversationViewSet(viewsets.ReadOnlyModelViewSet):
	serializer_class = ConversationSerializer
	permission_classes = [permissions.IsAuthenticated]

	def get_queryset(self):
		user = self.request.user
		if not getattr(user, 'is_authenticated', False):
			return Conversation.objects.none()
		queryset = (
			Conversation.objects.filter(
				models.Q(members=user) |
				models.Q(partnership__user_a=user) |
				models.Q(partnership__user_b=user) |
				models.Q(goal__members=user)
			)
			.distinct()
			.annotate(
			archived_for_user=models.Exists(
				ConversationMembership.objects.filter(
					conversation_id=models.OuterRef('pk'),
					user=user,
					archived_at__isnull=False,
				)
			),
			unread_count=models.Count(
				'messages',
				filter=models.Q(messages__is_read=False) & ~models.Q(messages__sender=user),
			)
			)
		)
		if self.action == 'archived':
			queryset = queryset.filter(archived_for_user=True)
		elif self.action != 'restore':
			queryset = queryset.filter(archived_for_user=False)
		return queryset.distinct().order_by('-updated_at')

	@action(detail=False, methods=['get'], url_path='archived')
	def archived(self, request):
		return Response(ConversationSerializer(self.get_queryset(), many=True, context={'request': request}).data)

	@action(detail=True, methods=['post'], url_path='archive')
	def archive(self, request, pk=None):
		conversation = self.get_object()
		membership, _ = ConversationMembership.objects.get_or_create(
			conversation=conversation,
			user=request.user,
		)
		membership.archived_at = timezone.now()
		membership.save(update_fields=['archived_at', 'updated_at'])
		return Response({'detail': 'Conversation archived.'})

	@action(detail=True, methods=['post'], url_path='restore')
	def restore(self, request, pk=None):
		conversation = self.get_object()
		membership, _ = ConversationMembership.objects.get_or_create(
			conversation=conversation,
			user=request.user,
		)
		membership.archived_at = None
		membership.save(update_fields=['archived_at', 'updated_at'])
		return Response(ConversationSerializer(conversation, context={'request': request}).data)

	@extend_schema(
		responses={200: ConversationMediaSerializer(many=True)},
		description='List media attachments for a conversation.'
	)
	@action(detail=True, methods=['get'], url_path='media')
	def media(self, request, pk=None):
		conversation = self.get_object()
		qs = (
			conversation.messages.select_related('sender')
			.exclude(models.Q(attachment__isnull=True) | models.Q(attachment=''))
			.order_by('-created_at')
		)
		return Response(ConversationMediaSerializer(qs, many=True, context={'request': request}).data)

	@extend_schema(
		request=ConversationRenameRequestSerializer,
		responses={200: ConversationSerializer, 400: DetailResponseSerializer, 403: DetailResponseSerializer},
		description='Rename a group conversation.'
	)
	@action(detail=True, methods=['post'], url_path='rename-group')
	def rename_group(self, request, pk=None):
		conversation = self.get_object()
		if not conversation.is_group:
			return Response({'detail': 'Only group conversations can be renamed.'}, status=status.HTTP_400_BAD_REQUEST)
		if not _user_is_member_of_conversation(request.user.id, conversation):
			return Response({'detail': 'You are not part of this conversation.'}, status=status.HTTP_403_FORBIDDEN)

		serializer = ConversationRenameRequestSerializer(data=request.data)
		serializer.is_valid(raise_exception=True)
		conversation.name = serializer.validated_data['name'].strip()
		conversation.save(update_fields=['name', 'updated_at'])
		return Response(ConversationSerializer(conversation, context={'request': request}).data, status=status.HTTP_200_OK)


class MessageViewSet(
	mixins.CreateModelMixin,
	mixins.ListModelMixin,
	mixins.RetrieveModelMixin,
	viewsets.GenericViewSet,
):
	serializer_class = MessageSerializer
	permission_classes = [permissions.IsAuthenticated]

	def get_queryset(self):
		user = self.request.user
		qs = (
			Message.objects.filter(
				models.Q(conversation__members=user) |
				models.Q(conversation__partnership__user_a=user) |
				models.Q(conversation__partnership__user_b=user) |
				models.Q(conversation__goal__members=user)
			)
			.distinct()
			.order_by('-created_at')
		)
		conversation_id = self.request.query_params.get('conversation')
		if conversation_id:
			qs = qs.filter(conversation_id=conversation_id)
		return qs

	def perform_create(self, serializer):
		conversation = serializer.validated_data['conversation']
		user = self.request.user
		# Ensure user belongs to the conversation's partnership
		if not _user_is_member_of_conversation(user.id, conversation):
			raise PermissionDenied('You are not part of this conversation.')
		message = serializer.save(sender=user)
		self._broadcast_conversation_update(conversation_id=conversation.id)
		return message

	def _broadcast_conversation_update(self, *, conversation_id: int):
		"""Best-effort realtime update for ws/conversations/."""
		channel_layer = get_channel_layer()
		if not channel_layer:
			return
		conv = Conversation.objects.select_related('partnership', 'goal').prefetch_related('members').get(id=conversation_id)
		user_ids = list(conv.members.values_list('id', flat=True))
		if not user_ids:
			if conv.partnership_id:
				user_ids = [conv.partnership.user_a_id, conv.partnership.user_b_id]
			elif conv.goal_id:
				user_ids = list(conv.goal.members.values_list('id', flat=True))
		last_msg = (
			Message.objects.select_related('sender')
			.filter(conversation_id=conversation_id)
			.order_by('-created_at')
			.first()
		)
		last_message_payload = MessageSerializer(last_msg, context={'request': getattr(self, 'request', None)}).data if last_msg else None
		member_names = [u.name for u in conv.members.all()] if conv.members.exists() else []
		for uid in user_ids:
			if ConversationMembership.objects.filter(
				conversation_id=conversation_id,
				user_id=uid,
				archived_at__isnull=False,
			).exists():
				continue
			unread_count = (
				Message.objects.filter(conversation_id=conversation_id, is_read=False)
				.exclude(sender_id=uid)
				.count()
			)
			payload = {
				'id': conv.id,
				'partnership': conv.partnership_id,
				'goal': conv.goal_id,
				'is_group': conv.is_group,
				'display_name': (conv.name or conv.goal.title) if conv.is_group else None,
				'name': conv.name,
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


	@extend_schema(
		responses={200: MessageSerializer, 400: DetailResponseSerializer, 403: DetailResponseSerializer},
		description='Mark a message as read by the recipient.'
	)
	@action(detail=True, methods=['post'])
	def mark_read(self, request, pk=None):
		message = self.get_object()
		user = request.user
		# Only allow the partner (not sender) to mark as read
		if message.sender == user:
			return Response({'detail': 'Sender cannot mark message as read.'}, status=status.HTTP_400_BAD_REQUEST)
		if not _user_is_member_of_conversation(user.id, message.conversation):
			return Response({'detail': 'You are not part of this conversation.'}, status=status.HTTP_403_FORBIDDEN)
		message.is_read = True
		message.save(update_fields=['is_read'])
		self._broadcast_conversation_update(conversation_id=message.conversation_id)
		return Response(MessageSerializer(message, context={'request': request}).data)

	@extend_schema(
		responses={200: MessageSerializer, 400: DetailResponseSerializer, 403: DetailResponseSerializer},
		description='Recall a message sent by the current user within the configured recall window.',
	)
	@action(detail=True, methods=['post'], url_path='recall')
	def recall(self, request, pk=None):
		message = self.get_object()
		if message.sender_id != request.user.id:
			return Response({'detail': 'Only the sender can recall this message.'}, status=status.HTTP_403_FORBIDDEN)
		if message.kind != Message.KIND_USER:
			return Response({'detail': 'System messages cannot be recalled.'}, status=status.HTTP_400_BAD_REQUEST)
		if message.recalled_at:
			return Response(MessageSerializer(message, context={'request': request}).data)
		window = int(getattr(settings, 'MESSAGE_RECALL_WINDOW_MINUTES', 15))
		if message.created_at < timezone.now() - timedelta(minutes=window):
			return Response(
				{'detail': f'Messages can only be recalled within {window} minutes.'},
				status=status.HTTP_400_BAD_REQUEST,
			)
		if message.attachment:
			message.attachment.delete(save=False)
		message.text = ''
		message.attachment = None
		message.attachment_name = ''
		message.attachment_mime = ''
		message.attachment_size = None
		message.recalled_at = timezone.now()
		message.save(update_fields=[
			'text', 'attachment', 'attachment_name', 'attachment_mime',
			'attachment_size', 'recalled_at', 'updated_at',
		])
		payload = MessageSerializer(message, context={'request': request}).data
		channel_layer = get_channel_layer()
		if channel_layer:
			async_to_sync(channel_layer.group_send)(
				f'chat_{message.conversation_id}',
				{'type': 'chat.message.updated', 'message': payload},
			)
		self._broadcast_conversation_update(conversation_id=message.conversation_id)
		return Response(payload)


class GoalCheckinViewSet(viewsets.ModelViewSet):
	serializer_class = GoalCheckinSerializer
	permission_classes = [permissions.IsAuthenticated]
	http_method_names = ['get', 'post', 'patch', 'head', 'options']
	ordering_fields = ['scheduled_for', 'submitted_at', 'created_at']
	ordering = ['-scheduled_for', '-created_at']

	def get_queryset(self):
		user = self.request.user
		today = dt_to_local_date(timezone.now(), get_user_tzinfo(user))
		GoalCheckin.objects.filter(
			status=GoalCheckin.STATUS_PENDING,
			scheduled_for__lt=today,
		).update(status=GoalCheckin.STATUS_MISSED)
		queryset = (
			GoalCheckin.objects.select_related('goal', 'user')
			.prefetch_related('reactions__user')
			.filter(
				models.Q(goal__user=user)
				| models.Q(goal__members=user)
				| models.Q(goal__partnership__user_a=user)
				| models.Q(goal__partnership__user_b=user)
			)
			.distinct()
		)
		goal_id = self.request.query_params.get('goal')
		if goal_id:
			queryset = queryset.filter(goal_id=goal_id)
		return queryset

	def _assert_goal_member(self, goal):
		if self.request.user.id not in _goal_member_ids(goal):
			raise PermissionDenied('You are not a member of this goal.')

	def _save_submission(self, serializer):
		retention_days = int(getattr(settings, 'CHECKIN_EVIDENCE_RETENTION_DAYS', 30))
		checkin = serializer.save(
			user=self.request.user,
			submitted_at=timezone.now(),
			evidence_expires_at=timezone.now() + timedelta(days=retention_days),
		)
		self._award_badge_if_earned(checkin)
		return checkin

	def _create_checkin_message(self, checkin):
		conversation = _ensure_goal_conversation(checkin.goal, self.request.user)
		Message.objects.create(
			conversation=conversation,
			sender=self.request.user,
			kind=Message.KIND_CHECKIN,
			metadata={
				'checkin_id': checkin.id,
				'goal_id': checkin.goal_id,
				'goal_title': checkin.goal.title,
				'status': checkin.status,
				'completion_percent': checkin.completion_percent,
				'blocker': checkin.blocker,
				'has_evidence': bool(checkin.evidence),
			},
		)

	def create(self, request, *args, **kwargs):
		serializer = self.get_serializer(data=request.data)
		serializer.is_valid(raise_exception=True)
		goal = serializer.validated_data['goal']
		self._assert_goal_member(goal)
		existing = GoalCheckin.objects.filter(
			goal=goal,
			user=request.user,
			scheduled_for=serializer.validated_data['scheduled_for'],
		).first()
		if existing and existing.status not in {GoalCheckin.STATUS_PENDING, GoalCheckin.STATUS_MISSED}:
			return Response({'detail': 'A check-in has already been submitted for this date.'}, status=status.HTTP_409_CONFLICT)
		if existing:
			serializer = self.get_serializer(existing, data=request.data, partial=True)
			serializer.is_valid(raise_exception=True)
		checkin = self._save_submission(serializer)
		self._create_checkin_message(checkin)
		return Response(self.get_serializer(checkin).data, status=status.HTTP_200_OK if existing else status.HTTP_201_CREATED)

	def perform_update(self, serializer):
		if serializer.instance.user_id != self.request.user.id:
			raise PermissionDenied('Only the check-in author can update it.')
		goal = serializer.validated_data.get('goal', serializer.instance.goal)
		self._assert_goal_member(goal)
		self._save_submission(serializer)

	def _award_badge_if_earned(self, checkin):
		member_ids = set(_goal_member_ids(checkin.goal))
		if not member_ids:
			return
		on_time_ids = set(
			GoalCheckin.objects.filter(
				goal=checkin.goal,
				scheduled_for=checkin.scheduled_for,
				user_id__in=member_ids,
				status__in=[GoalCheckin.STATUS_COMPLETED, GoalCheckin.STATUS_PARTIAL, GoalCheckin.STATUS_BLOCKED],
				submitted_at__date__lte=checkin.scheduled_for,
			).values_list('user_id', flat=True)
		)
		if on_time_ids == member_ids:
			GoalCheckinBadge.objects.get_or_create(
				goal=checkin.goal,
				scheduled_for=checkin.scheduled_for,
			)

	@action(detail=True, methods=['post'], url_path='react')
	def react(self, request, pk=None):
		checkin = self.get_object()
		serializer = GoalCheckinReactionRequestSerializer(data=request.data)
		serializer.is_valid(raise_exception=True)
		reaction, _ = GoalCheckinReaction.objects.update_or_create(
			checkin=checkin,
			user=request.user,
			defaults={'reaction': serializer.validated_data['reaction']},
		)
		checkin._prefetched_objects_cache = {}
		return Response(self.get_serializer(checkin).data)

	@action(detail=True, methods=['get'], url_path='evidence')
	def evidence(self, request, pk=None):
		checkin = self.get_object()
		if not checkin.evidence:
			return Response({'detail': 'No evidence is attached.'}, status=status.HTTP_404_NOT_FOUND)
		if checkin.evidence_expires_at and checkin.evidence_expires_at <= timezone.now():
			return Response({'detail': 'This evidence has expired.'}, status=status.HTTP_410_GONE)
		if checkin.evidence_view_once and checkin.user_id != request.user.id:
			_, created = GoalCheckinEvidenceView.objects.get_or_create(checkin=checkin, user=request.user)
			if not created:
				return Response({'detail': 'This view-once evidence has already been opened.'}, status=status.HTTP_410_GONE)
		filename = checkin.evidence.name.rsplit('/', 1)[-1]
		response = FileResponse(checkin.evidence.open('rb'), as_attachment=False, filename=filename)
		response['Cache-Control'] = 'private, no-store, max-age=0'
		response['Pragma'] = 'no-cache'
		response['X-Content-Type-Options'] = 'nosniff'
		return response


class DevicePushTokenViewSet(viewsets.GenericViewSet):
	permission_classes = [permissions.IsAuthenticated]
	serializer_class = DevicePushTokenRegisterSerializer

	@extend_schema(
		request=DevicePushTokenRegisterSerializer,
		responses={200: DetailResponseSerializer},
		description='Register or refresh a mobile push token for the current user.',
	)
	@action(detail=False, methods=['post'])
	def register(self, request):
		serializer = DevicePushTokenRegisterSerializer(data=request.data)
		serializer.is_valid(raise_exception=True)
		data = serializer.validated_data
		with transaction.atomic():
			DevicePushToken.objects.filter(token=data['token']).exclude(
				user=request.user,
				device_id=data['device_id'],
			).delete()
			DevicePushToken.objects.update_or_create(
				user=request.user,
				device_id=data['device_id'],
				defaults={
					'token': data['token'],
					'platform': data['platform'],
					'is_active': True,
				},
			)
		return Response({'detail': 'Device registered.'})

	@extend_schema(
		request=DevicePushTokenUnregisterSerializer,
		responses={200: DetailResponseSerializer},
		description='Deactivate a mobile push token owned by the current user.',
	)
	@action(detail=False, methods=['post'])
	def unregister(self, request):
		serializer = DevicePushTokenUnregisterSerializer(data=request.data)
		serializer.is_valid(raise_exception=True)
		DevicePushToken.objects.filter(
			user=request.user,
			token=serializer.validated_data['token'],
		).update(is_active=False)
		return Response({'detail': 'Device unregistered.'})


class NotificationViewSet(viewsets.ReadOnlyModelViewSet):
	serializer_class = NotificationSerializer
	permission_classes = [permissions.IsAuthenticated]

	def get_queryset(self):
		return Notification.objects.filter(user=self.request.user).order_by('-created_at')

	@extend_schema(
		responses={200: NotificationMarkAllReadResponseSerializer},
		description='Mark all notifications as read for current user.'
	)
	@action(detail=False, methods=['post'])
	def mark_all_read(self, request):
		qs = self.get_queryset().filter(is_read=False)
		count = qs.update(is_read=True)
		return Response({'marked_read': count})

	@extend_schema(
		responses={200: NotificationSerializer},
		description='Mark a single notification as read.'
	)
	@action(detail=True, methods=['post'])
	def mark_read(self, request, pk=None):
		notification = self.get_object()
		notification.is_read = True
		notification.save(update_fields=['is_read'])
		return Response(NotificationSerializer(notification).data)


class WaitlistViewSet(viewsets.ModelViewSet):
	"""Handle waitlist entries.

	- Anyone can join the waitlist (unauthenticated POST).
	- Only admins can list, retrieve, update or delete entries.
	"""
	serializer_class = WaitlisterSerializer

	def get_queryset(self):
		# Only admins should be able to see the waitlist.
		user = self.request.user
		if not user.is_authenticated or not user.is_staff:
			return Waitlister.objects.none()
		return Waitlister.objects.all().order_by('-created_at')

	def get_permissions(self):
		if self.action in ['create', 'join']:
			return [permissions.AllowAny()]
		return [permissions.IsAdminUser()]

	def get_throttles(self):
		if self.action in ['create', 'join']:
			self.throttle_scope = 'waitlist'
			return [ScopedRateThrottle()]
		return super().get_throttles()


	@extend_schema(
		request=WaitlisterSerializer,
		responses={201: WaitlisterSerializer, 400: DetailResponseSerializer},
		description='Public endpoint to join the waitlist.'
	)
	@action(detail=False, methods=['post'])
	def join(self, request):
		"""Public endpoint for users to join the waitlist.

		POST /api-v1/waitlist/join/
		"""
		serializer = self.get_serializer(data=request.data)
		if not serializer.is_valid():
			# Flatten validation errors into a single detail message
			# e.g. {"detail": "This email is already on the waitlist."}
			errors = serializer.errors
			first_key = next(iter(errors)) if errors else None
			first_error = errors[first_key][0] if first_key is not None else "Invalid data."
			return Response({"detail": str(first_error)}, status=status.HTTP_400_BAD_REQUEST)

		instance = serializer.save()
		return Response(self.get_serializer(instance).data, status=status.HTTP_201_CREATED)

	@action(detail=False, methods=['get'], url_path='download-waitlist', permission_classes=[permissions.IsAdminUser])
	def download_waitlist(self, request):
		"""Download all waitlisters as CSV for an authenticated admin."""
		import csv
		from django.http import HttpResponse
		qs = Waitlister.objects.all().order_by('-created_at')
		response = HttpResponse(content_type='text/csv')
		response['Content-Disposition'] = 'attachment; filename="waitlist.csv"'
		writer = csv.writer(response)
		writer.writerow(['id', 'email', 'name', 'age', 'sex', 'country', 'created_at', 'updated_at'])
		for w in qs:
			writer.writerow([
				w.id, w.email, w.name, w.age, w.sex, w.country, w.created_at, w.updated_at
			])
		return response


class StatsViewSet(viewsets.ViewSet):
	permission_classes = [permissions.IsAuthenticated]

	def _get_user_tzinfo(self, user):
		"""Return tzinfo for day-boundary calculations."""
		return get_user_tzinfo(user)

	def _dt_to_local_date(self, dt, tzinfo):
		return dt_to_local_date(dt, tzinfo)

	def _longest_consecutive_days(self, dates) -> int:
		unique = sorted(set(dates))
		if not unique:
			return 0
		longest = 1
		current = 1
		prev = unique[0]
		for d in unique[1:]:
			if d == (prev + timedelta(days=1)):
				current += 1
			else:
				current = 1
			if current > longest:
				longest = current
			prev = d
		return longest

	def _current_streak_days(self, dates, end_date) -> int:
		"""Consecutive active days ending on end_date.

		If end_date is not active, current streak is 0.
		"""
		if not dates or end_date not in dates:
			return 0
		count = 1
		cursor = end_date
		while (cursor - timedelta(days=1)) in dates:
			count += 1
			cursor = cursor - timedelta(days=1)
		return count

	@extend_schema(
		responses={200: LongestStreakResponseSerializer},
		description=(
			"Get the current user's streak stats (longest + current consecutive-day activity streak). "
			"A day counts as active if the user has ANY of: "
			"(1) a timer session started, (2) evidence submitted, (3) a task completed, "
			"(4) a goal created/updated, (5) a message sent, (6) a login. "
			"Day boundaries use the user's Profile.time_zone when available. "
			"Current streak is the consecutive-day streak ending today (in the user's timezone)."
		),
	)
	@action(detail=False, methods=['get'], url_path='longest-streak')
	def longest_streak(self, request):
		user = request.user
		tzinfo = self._get_user_tzinfo(user)
		active_dates = set()

		for activity_date in (
			UserDailyActivity.objects.filter(user=user)
			.values_list('activity_date', flat=True)
			.iterator()
		):
			if activity_date:
				active_dates.add(activity_date)

		# Backward-compatibility path: if no normalized rows exist yet,
		# reconstruct from historical model data.
		if not active_dates:
			# Count login as activity so users can build a streak by showing up daily.
			# `last_login` only stores one timestamp; include Knox token creation dates
			# to preserve historical login days for streak calculations.
			for token_created_at in (
				AuthToken.objects.filter(user=user)
				.values_list('created', flat=True)
				.iterator()
			):
				d = self._dt_to_local_date(token_created_at, tzinfo)
				if d:
					active_dates.add(d)

			login_d = self._dt_to_local_date(getattr(user, 'last_login', None), tzinfo)
			if login_d:
				active_dates.add(login_d)

			for started_at, created_at in (
				TimerSession.objects.filter(user=user)
				.values_list('started_at', 'created_at')
				.iterator()
			):
				d = self._dt_to_local_date(started_at or created_at, tzinfo)
				if d:
					active_dates.add(d)

			for submitted_at, created_at in (
				Evidence.objects.filter(submitted_by=user)
				.values_list('submitted_at', 'created_at')
				.iterator()
			):
				d = self._dt_to_local_date(submitted_at or created_at, tzinfo)
				if d:
					active_dates.add(d)

			for updated_at, created_at in (
				Task.objects.filter(owner=user, status=Task.STATUS_COMPLETED)
				.values_list('updated_at', 'created_at')
				.iterator()
			):
				d = self._dt_to_local_date(updated_at or created_at, tzinfo)
				if d:
					active_dates.add(d)


			# Include goals owned by user or partnership goals where user is a partner
			for created_at, updated_at in (
				Goal.objects.filter(
					models.Q(user=user) |
					models.Q(partnership__user_a=user) |
					models.Q(partnership__user_b=user)
				)
				.values_list('created_at', 'updated_at')
				.iterator()
			):
				created_d = self._dt_to_local_date(created_at, tzinfo)
				if created_d:
					active_dates.add(created_d)
				updated_d = self._dt_to_local_date(updated_at, tzinfo)
				if updated_d:
					active_dates.add(updated_d)

			for created_at in (
				Message.objects.filter(sender=user)
				.values_list('created_at', flat=True)
				.iterator()
			):
				d = self._dt_to_local_date(created_at, tzinfo)
				if d:
					active_dates.add(d)

		local_today = timezone.localtime(timezone.now(), tzinfo).date()
		longest = self._longest_consecutive_days(active_dates)
		current = self._current_streak_days(active_dates, local_today)
		return Response(
			{'longest_streak_count': int(longest), 'current_streak_count': int(current)},
			status=status.HTTP_200_OK,
		)


