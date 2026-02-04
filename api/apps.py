from django.apps import AppConfig


class ApiConfig(AppConfig):
    name = 'api'

    def ready(self):
        # Register drf-spectacular extensions (OpenAPI schema only).
        from . import spectacular_extensions  # noqa: F401
