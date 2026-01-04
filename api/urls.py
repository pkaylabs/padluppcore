from django.urls import include, path
from knox import views as knox_views
from drf_spectacular.utils import extend_schema_view, extend_schema
from rest_framework.routers import DefaultRouter
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

from api.serializers import LogoutResponseSerializer

from .viewsets import (
	AuthViewSet,
	BuddyViewSet,
	ConversationViewSet,
	EvidenceViewSet,
	EventViewSet,
	GoalViewSet,
	MatchViewSet,
	NotificationViewSet,
	MessageViewSet,
	OnboardingViewSet,
	PartnershipViewSet,
	SubTaskViewSet,
	TaskViewSet,
	TimerSessionViewSet,
	WaitlistViewSet,
)


router = DefaultRouter()
router.register('onboarding', OnboardingViewSet, basename='onboarding')
router.register('auth', AuthViewSet, basename='auth')
router.register('goals', GoalViewSet, basename='goals')
router.register('partnerships', PartnershipViewSet, basename='partnerships')
router.register('matches', MatchViewSet, basename='matches')
router.register('buddies', BuddyViewSet, basename='buddies')
router.register('tasks', TaskViewSet, basename='tasks')
router.register('subtasks', SubTaskViewSet, basename='subtasks')
router.register('timer-sessions', TimerSessionViewSet, basename='timer-sessions')
router.register('evidences', EvidenceViewSet, basename='evidences')
router.register('events', EventViewSet, basename='events')
router.register('notifications', NotificationViewSet, basename='notifications')
router.register('conversations', ConversationViewSet, basename='conversations')
router.register('messages', MessageViewSet, basename='messages')
router.register('waitlist', WaitlistViewSet, basename='waitlist')



# Decorate knox logout view for schema
LogoutViewSchema = extend_schema_view(
	post=extend_schema(
		responses={200: LogoutResponseSerializer},
		description="Logout endpoint. Invalidates the token. Returns a detail message."
	)
)(knox_views.LogoutView)

urlpatterns = [
	path('schema/', SpectacularAPIView.as_view(), name='schema'),
	path('docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
	path('auth/logout/', LogoutViewSchema.as_view(), name='knox_logout'),
	path('', include(router.urls)),
]

