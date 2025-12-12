from django.urls import include, path
from knox import views as knox_views
from rest_framework.routers import DefaultRouter
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

from .viewsets import (
	AuthViewSet,
	ConversationViewSet,
	EvidenceViewSet,
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
router.register('tasks', TaskViewSet, basename='tasks')
router.register('subtasks', SubTaskViewSet, basename='subtasks')
router.register('timer-sessions', TimerSessionViewSet, basename='timer-sessions')
router.register('evidences', EvidenceViewSet, basename='evidences')
router.register('notifications', NotificationViewSet, basename='notifications')
router.register('conversations', ConversationViewSet, basename='conversations')
router.register('messages', MessageViewSet, basename='messages')
router.register('waitlist', WaitlistViewSet, basename='waitlist')


urlpatterns = [
	path('schema/', SpectacularAPIView.as_view(), name='schema'),
	path('docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
	path('auth/logout/', knox_views.LogoutView.as_view(), name='knox_logout'),
	path('', include(router.urls)),
]

