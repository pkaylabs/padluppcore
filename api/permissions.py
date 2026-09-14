import secrets

from django.conf import settings
from rest_framework.permissions import BasePermission


class HasCronSecret(BasePermission):
    message = 'Valid cron credentials are required.'

    def has_permission(self, request, view):
        configured_secret = getattr(settings, 'CRON_SHARED_SECRET', '')
        if not configured_secret:
            return bool(settings.DEBUG)

        provided_secret = request.headers.get('X-Padlupp-Cron-Secret', '')
        return secrets.compare_digest(provided_secret, configured_secret)
