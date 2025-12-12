import os

from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
from django.core.asgi import get_asgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'padluppcore.settings')

django_asgi_app = get_asgi_application()

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
