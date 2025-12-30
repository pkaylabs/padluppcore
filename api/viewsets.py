from django.contrib.auth import authenticate
from django.db import models
from knox.models import AuthToken
from rest_framework import permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from accounts.models import User
from .models import BuddyRequest, Conversation, Evidence, Event, Goal, Match, Notification, Partnership, Profile, SubTask, Task, TimerSession, Message, Waitlister
from .serializers import (
	BuddyConnectSerializer,
	BuddyFinderProfileSerializer,
	BuddyRequestSerializer,
	ConversationSerializer,
	EvidenceSerializer,
	EventxSerializer,
	GoalSerializer,
	MatchSerializer,
	NotificationSerializer,
	PartnershipSerializer,
	ProfileSerializer,
	SubTaskSerializer,
	TaskSerializer,
	TimerSessionSerializer,
	MessageSerializer,
	UserSerializer,
	WaitlisterSerializer,
)


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

	@action(detail=False, methods=['get'], url_path='finder')
	def finder(self, request):
		"""List profiles that have similar experiences to the current user.

		- Excludes existing buddy connections.
		- Includes profiles with pending outgoing buddy requests.
		- Adds `connection_status` = pending|none.
		"""
		user = request.user
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

		excluded_user_ids = set(buddy_user_ids) | {user.id}

		# crude similarity: match on keywords from the user's experience
		experience_text = (profile.experience or '').strip()
		keywords = [w.strip(' ,.;:!"\'()[]{}').lower() for w in experience_text.split()]
		keywords = [w for w in keywords if len(w) >= 4]
		keywords = list(dict.fromkeys(keywords))[:6]

		similarity_q = models.Q()
		for word in keywords:
			similarity_q |= models.Q(experience__icontains=word)

		qs = Profile.objects.exclude(user_id__in=excluded_user_ids)
		if similarity_q:
			qs = qs.filter(similarity_q | models.Q(user_id__in=pending_to_user_ids))
		else:
			# If no experience yet, only show pending requests (if any)
			qs = qs.filter(user_id__in=pending_to_user_ids)

		qs = qs.distinct().order_by('-created_at')
		page = None
		if hasattr(self, 'paginate_queryset'):
			page = self.paginate_queryset(qs)
		serializer = BuddyFinderProfileSerializer(
			page or qs,
			many=True,
			context={
				'pending_to_user_ids': pending_to_user_ids,
				'pending_request_id_by_to_user_id': pending_request_id_by_to_user_id,
			},
		)
		if page is not None:
			return self.get_paginated_response(serializer.data)
		return Response(serializer.data)

	@action(detail=False, methods=['post'], url_path='connect')
	def connect(self, request):
		"""Send a buddy connection request to another user."""
		serializer = BuddyConnectSerializer(data=request.data)
		serializer.is_valid(raise_exception=True)
		to_user = serializer.validated_data['to_user']
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
			defaults={'status': BuddyRequest.STATUS_PENDING},
		)
		if not created:
			if buddy_request.status == BuddyRequest.STATUS_PENDING:
				return Response({'detail': 'Connection request already pending.'}, status=status.HTTP_400_BAD_REQUEST)
			# If previously rejected/accepted, reset to pending
			buddy_request.status = BuddyRequest.STATUS_PENDING
			buddy_request.responded_at = None
			buddy_request.save(update_fields=['status', 'responded_at', 'updated_at'])

		return Response(BuddyRequestSerializer(buddy_request).data, status=status.HTTP_201_CREATED)

	@action(detail=False, methods=['get'], url_path='invitations')
	def invitations(self, request):
		"""List pending buddy requests sent to the current user."""
		qs = BuddyRequest.objects.filter(
			to_user=request.user,
			status=BuddyRequest.STATUS_PENDING,
		).order_by('-created_at')
		return Response(BuddyRequestSerializer(qs, many=True).data)

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
		Conversation.objects.get_or_create(partnership=partnership)

		return Response({'detail': 'Accepted.', 'partnership_id': partnership.id}, status=status.HTTP_200_OK)

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

	@action(detail=False, methods=['get'], url_path='connections')
	def connections(self, request):
		"""Return current user's buddy connections as profiles."""
		user = request.user
		buddy_ids = self._buddy_user_ids(user)
		qs = Profile.objects.filter(user_id__in=buddy_ids).order_by('-created_at')
		return Response(ProfileSerializer(qs, many=True).data)


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
			raise permissions.PermissionDenied('Only the creator can update this event.')
		serializer.save()

	def perform_destroy(self, instance):
		'''Only the creator can delete the event.'''
		if instance.creator_id != self.request.user.id:
			raise permissions.PermissionDenied('Only the creator can delete this event.')
		instance.delete()

	@action(detail=False, methods=['get'], url_path='created')
	def created(self, request):
		'''Get events created by the user.'''
		qs = Event.objects.filter(creator=request.user).order_by('-start_date', '-start_time', '-created_at')
		page = self.paginate_queryset(qs)
		serializer = self.get_serializer(page or qs, many=True)
		if page is not None:
			return self.get_paginated_response(serializer.data)
		return Response(serializer.data)

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

	@action(detail=True, methods=['post'], url_path='join')
	def join(self, request, pk=None):
		'''Join the event as a participant.'''
		event = self.get_object()
		event.participants.add(request.user)
		return Response(self.get_serializer(event).data, status=status.HTTP_200_OK)


class OnboardingViewSet(viewsets.ViewSet):
	permission_classes = [permissions.AllowAny]

	@action(detail=False, methods=['post'])
	def register(self, request):
		email = request.data.get('email')
		password = request.data.get('password')
		name = request.data.get('name')
		phone = request.data.get('phone')

		if not email or not password or not name:
			return Response({'detail': 'email, password and name are required.'}, status=status.HTTP_400_BAD_REQUEST)

		if User.objects.filter(email=email).exists():
			return Response({'detail': 'Email already in use.'}, status=status.HTTP_400_BAD_REQUEST)

		user = User.objects.create_user(email=email, password=password, name=name, phone=phone)
		Profile.objects.get_or_create(user=user)
		# auto-login after registration
		token = AuthToken.objects.create(user)[1]
		return Response({'user': UserSerializer(user).data, 'token': token}, status=status.HTTP_201_CREATED)

	@action(detail=False, methods=['get'], permission_classes=[permissions.IsAuthenticated])
	def profile(self, request):
		profile, _ = Profile.objects.get_or_create(user=request.user)
		return Response(ProfileSerializer(profile).data)

	@profile.mapping.put
	def update_profile(self, request):
		profile, _ = Profile.objects.get_or_create(user=request.user)
		serializer = ProfileSerializer(profile, data=request.data)
		serializer.is_valid(raise_exception=True)
		serializer.save()
		return Response(serializer.data)

	@profile.mapping.patch
	def partial_update_profile(self, request):
		profile, _ = Profile.objects.get_or_create(user=request.user)
		serializer = ProfileSerializer(profile, data=request.data, partial=True)
		serializer.is_valid(raise_exception=True)
		serializer.save()
		return Response(serializer.data)
	
	@action(detail=False, methods=['patch'], url_path='user-avatar', permission_classes=[permissions.IsAuthenticated])
	def user_avatar(self, request):
		user = request.user
		avatar = request.data.get('avatar')
		if not avatar:
			return Response({'detail': 'avatar is required.'}, status=status.HTTP_400_BAD_REQUEST)
		user.avatar = avatar
		user.save(update_fields=['avatar'])
		return Response(UserSerializer(user).data)
	
	@action(detail=False, methods=['post'], url_path='set-experience', permission_classes=[permissions.IsAuthenticated])
	def set_experience(self, request):
		profile, _ = Profile.objects.get_or_create(user=request.user)
		experience = request.data.get('experience')
		interests = request.data.get('interests')
		if experience is not None:
			profile.experience = experience
		if interests is not None:
			profile.interests = interests
		profile.save(update_fields=['experience', 'interests'])
		return Response(ProfileSerializer(profile).data)


class AuthViewSet(viewsets.ViewSet):
	permission_classes = [permissions.AllowAny]

	@action(detail=False, methods=['post'])
	def login(self, request):
		email = request.data.get('email')
		password = request.data.get('password')

		if not email or not password:
			return Response({'detail': 'email and password are required.'}, status=status.HTTP_400_BAD_REQUEST)

		user = authenticate(request, email=email, password=password)
		if not user:
			return Response({'detail': 'Invalid credentials.'}, status=status.HTTP_400_BAD_REQUEST)

		token = AuthToken.objects.create(user)[1]
		return Response({'user': UserSerializer(user).data, 'token': token}, status=status.HTTP_200_OK)


class GoalViewSet(viewsets.ModelViewSet):
	serializer_class = GoalSerializer
	permission_classes = [permissions.IsAuthenticated]

	def get_queryset(self):
		return Goal.objects.filter(user=self.request.user).order_by('-created_at')

	def perform_create(self, serializer):
		serializer.save(user=self.request.user)


class PartnershipViewSet(viewsets.ModelViewSet):
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

	@action(detail=False, methods=['get'])
	def discover(self, request):
		user = request.user

		# Exclude users already matched with (like/pass) or self
		swiped_user_ids = Match.objects.filter(from_user=user).values_list('to_user_id', flat=True)
		partner_user_ids = Partnership.objects.filter(
			models.Q(user_a=user) | models.Q(user_b=user)
		).values_list('user_a_id', 'user_b_id')
		partner_user_ids_flat = {uid for pair in partner_user_ids for uid in pair}

		excluded_ids = set(swiped_user_ids) | partner_user_ids_flat | {user.id}

		profiles = Profile.objects.exclude(user_id__in=excluded_ids)
		# TODO: later filter by goals, focus areas, time zone, etc.

		page = self.paginate_queryset(profiles)
		serializer = ProfileSerializer(page or profiles, many=True)
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
					Notification.objects.bulk_create([
						Notification(
							user=user_a,
							type='new_match',
							payload={'partner_id': user_b.id, 'partnership_id': partnership.id},
						),
						Notification(
							user=user_b,
							type='new_match',
							payload={'partner_id': user_a.id, 'partnership_id': partnership.id},
						),
					])

		return match


class TaskViewSet(viewsets.ModelViewSet):
	serializer_class = TaskSerializer
	permission_classes = [permissions.IsAuthenticated]

	def get_queryset(self):
		return Task.objects.filter(owner=self.request.user).order_by('-created_at')

	def perform_create(self, serializer):
		task = serializer.save(owner=self.request.user)
		# Notify partner (if any) about new task
		if task.partnership:
			partner = task.partnership.user_a if task.partnership.user_b == self.request.user else task.partnership.user_b
			Notification.objects.create(
				user=partner,
				type='new_task',
				payload={'task_id': task.id, 'title': task.title},
			)

	@action(detail=True, methods=['post'])
	def start_timer(self, request, pk=None):
		task = self.get_object()
		# End any existing open timer session for this user on this task
		TimerSession.objects.filter(task=task, user=request.user, ended_at__isnull=True).update(ended_at=models.F('created_at'))
		session = TimerSession.objects.create(task=task, user=request.user, started_at=models.functions.Now())
		if task.status == Task.STATUS_PLANNED:
			task.status = Task.STATUS_IN_PROGRESS
			task.save(update_fields=['status'])
		return Response(TimerSessionSerializer(session).data, status=status.HTTP_201_CREATED)

	@action(detail=True, methods=['post'])
	def stop_timer(self, request, pk=None):
		task = self.get_object()
		session = TimerSession.objects.filter(task=task, user=request.user, ended_at__isnull=True).order_by('-started_at').first()
		if not session:
			return Response({'detail': 'No active timer session.'}, status=status.HTTP_400_BAD_REQUEST)
		session.ended_at = models.functions.Now()
		session.save(update_fields=['ended_at'])
		return Response(TimerSessionSerializer(session).data)

	@action(detail=True, methods=['post'])
	def request_review(self, request, pk=None):
		task = self.get_object()
		if task.status not in [Task.STATUS_IN_PROGRESS, Task.STATUS_NEEDS_REVISION]:
			return Response({'detail': 'Task must be in progress or needs revision to request review.'}, status=status.HTTP_400_BAD_REQUEST)
		task.status = Task.STATUS_PENDING_REVIEW
		task.save(update_fields=['status'])
		# Notify partner that review is requested
		if task.partnership:
			partner = task.partnership.user_a if task.partnership.user_b == request.user else task.partnership.user_b
			Notification.objects.create(
				user=partner,
				type='review_requested',
				payload={'task_id': task.id, 'title': task.title},
			)
		return Response(TaskSerializer(task).data)

	@action(detail=True, methods=['post'])
	def mark_not_completed(self, request, pk=None):
		task = self.get_object()
		task.status = Task.STATUS_NOT_COMPLETED
		task.save(update_fields=['status'])
		return Response(TaskSerializer(task).data)

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
		task.save(update_fields=['status'])

		# Update latest evidence (if any)
		evidence = task.evidences.order_by('-submitted_at').first()
		if evidence:
			evidence.approved = True
			evidence.reviewer = request.user
			evidence.reviewed_at = models.functions.Now()
			evidence.save(update_fields=['approved', 'reviewer', 'reviewed_at'])

		# Notify task owner
		Notification.objects.create(
			user=task.owner,
			type='task_approved',
			payload={'task_id': task.id},
		)
		return Response(TaskSerializer(task).data)

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
		task.save(update_fields=['status'])

		# Update latest evidence (if any)
		evidence = task.evidences.order_by('-submitted_at').first()
		if evidence:
			evidence.approved = False
			evidence.reviewer = request.user
			evidence.reviewed_at = models.functions.Now()
			evidence.save(update_fields=['approved', 'reviewer', 'reviewed_at'])

		# Notify task owner with comment in payload
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
		evidence = serializer.save(submitted_by=self.request.user)
		# Notify partner that evidence was submitted
		task = evidence.task
		if task.partnership:
			partner = task.partnership.user_a if task.partnership.user_b == self.request.user else task.partnership.user_b
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
		return Conversation.objects.filter(
			models.Q(partnership__user_a=user) | models.Q(partnership__user_b=user)
		).order_by('-created_at')


class MessageViewSet(viewsets.ModelViewSet):
	serializer_class = MessageSerializer
	permission_classes = [permissions.IsAuthenticated]

	def get_queryset(self):
		user = self.request.user
		qs = Message.objects.filter(
			models.Q(conversation__partnership__user_a=user) |
			models.Q(conversation__partnership__user_b=user)
		).order_by('-created_at')
		conversation_id = self.request.query_params.get('conversation')
		if conversation_id:
			qs = qs.filter(conversation_id=conversation_id)
		return qs

	def perform_create(self, serializer):
		conversation = serializer.validated_data['conversation']
		user = self.request.user
		# Ensure user belongs to the conversation's partnership
		if user not in [conversation.partnership.user_a, conversation.partnership.user_b]:
			raise PermissionError('You are not part of this conversation.')
		message = serializer.save(sender=user)
		return message

	@action(detail=True, methods=['post'])
	def mark_read(self, request, pk=None):
		message = self.get_object()
		user = request.user
		# Only allow the partner (not sender) to mark as read
		if message.sender == user:
			return Response({'detail': 'Sender cannot mark message as read.'}, status=status.HTTP_400_BAD_REQUEST)
		if user not in [message.conversation.partnership.user_a, message.conversation.partnership.user_b]:
			return Response({'detail': 'You are not part of this conversation.'}, status=status.HTTP_403_FORBIDDEN)
		message.is_read = True
		message.save(update_fields=['is_read'])
		return Response(MessageSerializer(message).data)


class NotificationViewSet(viewsets.ModelViewSet):
	serializer_class = NotificationSerializer
	permission_classes = [permissions.IsAuthenticated]

	def get_queryset(self):
		return Notification.objects.filter(user=self.request.user).order_by('-created_at')

	@action(detail=False, methods=['post'])
	def mark_all_read(self, request):
		qs = self.get_queryset().filter(is_read=False)
		count = qs.update(is_read=True)
		return Response({'marked_read': count})

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
		# Allow unauthenticated access to download-waitlist endpoint
		if self.action in ['create', 'join', 'download_waitlist']:
			return [permissions.AllowAny()]
		return [permissions.IsAdminUser()]

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

	@action(detail=False, methods=['get'], url_path='download-waitlist', permission_classes=[permissions.AllowAny])
	def download_waitlist(self, request):
		"""Download all waitlisters as CSV (no auth required, for testing)."""
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


