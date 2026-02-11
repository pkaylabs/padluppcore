import os

from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
from django.conf import settings
from django.contrib.staticfiles.handlers import ASGIStaticFilesHandler
from django.core.asgi import get_asgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'padluppcore.settings')

django_asgi_app = get_asgi_application()

# When running via Daphne directly (not `manage.py runserver`), Django does not
# automatically serve staticfiles. This wrapper enables `/static/...` during
# local development so `/admin` assets load correctly.
if settings.DEBUG:
	django_asgi_app = ASGIStaticFilesHandler(django_asgi_app)

import api.routing

application = ProtocolTypeRouter({
	"http": django_asgi_app,
	"websocket": AuthMiddlewareStack(
		URLRouter(api.routing.websocket_urlpatterns)
	),
})

"""ASGI entrypoint for Django + Channels.

This exposes a ProtocolTypeRouter so HTTP traffic is handled by the
standard Django ASGI application and WebSocket traffic is routed through
Channels using the URL patterns defined in ``api.routing``.
"""
