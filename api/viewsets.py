from django.contrib.auth import authenticate
from django.db import models
from knox.models import AuthToken
from rest_framework import permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from accounts.models import User
from .models import Goal, Match, Partnership, Profile
from .serializers import GoalSerializer, MatchSerializer, PartnershipSerializer, ProfileSerializer, UserSerializer


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
				Partnership.objects.get_or_create(user_a=user_a, user_b=user_b)

		return match


