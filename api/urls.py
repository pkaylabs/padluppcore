from django.urls import include, path
from knox import views as knox_views
from rest_framework.routers import DefaultRouter
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

from .viewsets import AuthViewSet, GoalViewSet, MatchViewSet, OnboardingViewSet, PartnershipViewSet


router = DefaultRouter()
router.register('onboarding', OnboardingViewSet, basename='onboarding')
router.register('auth', AuthViewSet, basename='auth')
router.register('goals', GoalViewSet, basename='goals')
router.register('partnerships', PartnershipViewSet, basename='partnerships')
router.register('matches', MatchViewSet, basename='matches')


urlpatterns = [
	path('schema/', SpectacularAPIView.as_view(), name='schema'),
	path('docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
	path('auth/logout/', knox_views.LogoutView.as_view(), name='knox_logout'),
	path('', include(router.urls)),
]

