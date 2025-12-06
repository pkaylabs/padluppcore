from django.contrib.auth import authenticate
from django.db import models
from knox.models import AuthToken
from rest_framework import permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from accounts.models import User
from .models import Conversation, Evidence, Goal, Match, Notification, Partnership, Profile, SubTask, Task, TimerSession, Message
from .serializers import (
	ConversationSerializer,
	EvidenceSerializer,
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
)


class OnboardingViewSet(viewsets.ViewSet):
	permission_classes = [permissions.AllowAny]

	@action(detail=False, methods=['post'])
	def register(self, request):
		email = request.data.get('email')
		password = request.data.get('password')
		name = request.data.get('name')
		phone = request.data.get('phone')

		if not email or not password or not name or not phone:
			return Response({'detail': 'email, password, name and phone are required.'}, status=status.HTTP_400_BAD_REQUEST)

		if User.objects.filter(email=email).exists():
			return Response({'detail': 'Email already in use.'}, status=status.HTTP_400_BAD_REQUEST)

		user = User.objects.create_user(email=email, password=password, name=name, phone=phone)
		Profile.objects.get_or_create(user=user)
		return Response(UserSerializer(user).data, status=status.HTTP_201_CREATED)

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


