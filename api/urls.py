from django.urls import include, path
from rest_framework.routers import DefaultRouter
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

from .viewsets import OnboardingViewSet


router = DefaultRouter()
router.register('onboarding', OnboardingViewSet, basename='onboarding')


urlpatterns = [
	path('schema/', SpectacularAPIView.as_view(), name='schema'),
	path('docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
	path('', include(router.urls)),
]

