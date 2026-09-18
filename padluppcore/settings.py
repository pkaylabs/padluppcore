from pathlib import Path

import os
import sys
from django.core.exceptions import ImproperlyConfigured
from dotenv import load_dotenv
from datetime import timedelta

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Production can keep secrets outside the checkout via DJANGO_ENV_FILE. Local
# development retains compatibility with either historical .env location.
DJANGO_ENV_FILE = os.getenv('DJANGO_ENV_FILE', '').strip()
if DJANGO_ENV_FILE:
    load_dotenv(DJANGO_ENV_FILE)
else:
    load_dotenv(BASE_DIR / '.env')
    load_dotenv(Path(__file__).resolve().parent / '.env')


def env_bool(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {'1', 'true', 'yes', 'on'}


def env_list(name, default=()):
    value = os.getenv(name)
    if value is None:
        return list(default)
    return [item.strip() for item in value.split(',') if item.strip()]


DEBUG = env_bool('DJANGO_DEBUG', False)

SECRET_KEY = os.getenv('DJANGO_SECRET_KEY', '').strip()
if not SECRET_KEY:
    if DEBUG or 'test' in sys.argv:
        SECRET_KEY = 'dev-only-padlupp-secret-key-not-for-production'
    else:
        raise ImproperlyConfigured('DJANGO_SECRET_KEY must be set when DJANGO_DEBUG is disabled.')

ALLOWED_HOSTS = env_list(
    'DJANGO_ALLOWED_HOSTS',
    ('localhost', '127.0.0.1') if DEBUG else ('api.padlupp.com', '127.0.0.1'),
)

# --- CSRF / proxy settings for HTTPS behind a reverse proxy ---
# When running behind Nginx/Cloudflare/etc, Django may see the connection as HTTP
# unless we tell it to trust the forwarded proto header.
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
USE_X_FORWARDED_HOST = True

# Allow POSTs to the Django admin from the deployed domain.
# (Django requires scheme in CSRF_TRUSTED_ORIGINS.)
CSRF_TRUSTED_ORIGINS = env_list(
    'DJANGO_CSRF_TRUSTED_ORIGINS',
    ('http://localhost:8080', 'http://127.0.0.1:8080') if DEBUG else ('https://api.padlupp.com',),
)

SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
SECURE_SSL_REDIRECT = not DEBUG
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_HSTS_SECONDS = 31536000 if not DEBUG else 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_REFERRER_POLICY = 'same-origin'
X_FRAME_OPTIONS = 'DENY'


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # third party apps
    'corsheaders',
    'rest_framework',
    'knox',
    'drf_spectacular',
    'django_filters',
	'channels',
    
    # local apps
    'accounts.apps.AccountsConfig',
    'api.apps.ApiConfig',

]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'padluppcore.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'padluppcore.wsgi.application'
ASGI_APPLICATION = 'padluppcore.asgi.application'

# Channels: configure a channel layer so group_add/group_send work.
# - In dev / single-process Daphne, in-memory is fine.
# - In production (multiple workers/instances), install `channels-redis` and set REDIS_URL.
REDIS_URL = os.getenv('REDIS_URL', '').strip()
if REDIS_URL:
    CACHES = {
        'default': {
            'BACKEND': 'django.core.cache.backends.redis.RedisCache',
            'LOCATION': REDIS_URL,
        }
    }
    try:
        import channels_redis  # noqa: F401

        CHANNEL_LAYERS = {
            'default': {
                'BACKEND': 'channels_redis.core.RedisChannelLayer',
                'CONFIG': {
                    'hosts': [REDIS_URL],
                },
            }
        }
    except Exception:
        CHANNEL_LAYERS = {
            'default': {
                'BACKEND': 'channels.layers.InMemoryChannelLayer',
            }
        }
else:
    CACHES = {
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            'LOCATION': 'padluppcore',
        }
    }
    CHANNEL_LAYERS = {
        'default': {
            'BACKEND': 'channels.layers.InMemoryChannelLayer',
        }
    }


# Database
# https://docs.djangoproject.com/en/6.0/ref/settings/#databases

DATABASE_ENGINE = os.getenv('DATABASE_ENGINE', 'sqlite').strip().lower()

if DATABASE_ENGINE in {'postgres', 'postgresql', 'django.db.backends.postgresql'}:
    postgres_environment = {
        'POSTGRES_DB': ('NAME', os.getenv('POSTGRES_DB', '').strip()),
        'POSTGRES_USER': ('USER', os.getenv('POSTGRES_USER', '').strip()),
        'POSTGRES_PASSWORD': ('PASSWORD', os.getenv('POSTGRES_PASSWORD', '')),
        'POSTGRES_HOST': ('HOST', os.getenv('POSTGRES_HOST', '127.0.0.1').strip()),
        'POSTGRES_PORT': ('PORT', os.getenv('POSTGRES_PORT', '5432').strip()),
    }
    missing_postgres_settings = [
        name for name, (_, value) in postgres_environment.items() if not value
    ]
    if missing_postgres_settings:
        raise ImproperlyConfigured(
            'PostgreSQL is enabled but these settings are missing: '
            + ', '.join(missing_postgres_settings)
        )
    postgres_settings = {
        database_key: value
        for database_key, value in postgres_environment.values()
    }
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            **postgres_settings,
            'CONN_MAX_AGE': int(os.getenv('DATABASE_CONN_MAX_AGE', '60')),
            'CONN_HEALTH_CHECKS': True,
            'OPTIONS': {
                'sslmode': os.getenv('POSTGRES_SSLMODE', 'prefer').strip(),
            },
        }
    }
elif DATABASE_ENGINE in {'sqlite', 'sqlite3', 'django.db.backends.sqlite3'}:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': Path(os.getenv('DATABASE_PATH', BASE_DIR / 'db.sqlite3')),
        }
    }
else:
    raise ImproperlyConfigured(f'Unsupported DATABASE_ENGINE: {DATABASE_ENGINE}')


# Password validation
# https://docs.djangoproject.com/en/6.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


AUTH_USER_MODEL = 'accounts.User'

# Internationalization
# https://docs.djangoproject.com/en/6.0/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/6.0/howto/static-files/


STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles/'

STATICFILES_DIRS = [path for path in (BASE_DIR / 'static',) if path.exists()]

MEDIA_URL = '/assets/'
MEDIA_ROOT = Path(os.getenv('MEDIA_ROOT', BASE_DIR / 'assets'))

MESSAGE_RECALL_WINDOW_MINUTES = int(os.getenv('MESSAGE_RECALL_WINDOW_MINUTES', '15'))
CHECKIN_EVIDENCE_RETENTION_DAYS = int(os.getenv('CHECKIN_EVIDENCE_RETENTION_DAYS', '30'))

# Optional: used to build absolute media URLs when there is no request context.
# Example: https://api.padlupp.com
PUBLIC_BASE_URL = os.getenv('PUBLIC_BASE_URL', '')

# Django REST Framework Configuration
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'knox.auth.TokenAuthentication',
    ],
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
    'DEFAULT_FILTER_BACKENDS': [
        'django_filters.rest_framework.DjangoFilterBackend',
        'rest_framework.filters.SearchFilter',
        'rest_framework.filters.OrderingFilter',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20,
    'DEFAULT_THROTTLE_RATES': {
        'auth': '20/minute',
        'registration': '10/hour',
        'waitlist': '10/hour',
    },
}
# knox - token expiry
REST_KNOX = {
    'TOKEN_TTL': timedelta(hours=6),
}

# Browser clients are restricted to explicitly configured origins.
CORS_ALLOWED_ORIGINS = env_list(
    'DJANGO_CORS_ALLOWED_ORIGINS',
    ('http://localhost:8080', 'http://127.0.0.1:8080') if DEBUG else ('https://app.padlupp.com',),
)

# Paystack configuration
PAYSTACK_SECRET_KEY = os.getenv('PAYSTACK_SECRET_KEY', '')
PAYSTACK_PUBLIC_KEY = os.getenv('PAYSTACK_PUBLIC_KEY', '')
PAYSTACK_BASE_URL = os.getenv('PAYSTACK_BASE_URL', 'https://api.paystack.co')


# email settings
EMAIL_BACKEND = os.getenv('EMAIL_BACKEND', 'django.core.mail.backends.smtp.EmailBackend')
EMAIL_HOST = os.getenv('EMAIL_HOST', 'smtp.gmail.com')
EMAIL_PORT = int(os.getenv('EMAIL_PORT', '587'))
EMAIL_HOST_USER = os.getenv('EMAIL_HOST_USER', '')
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_HOST_PASSWORD', '')
EMAIL_USE_TLS = env_bool('EMAIL_USE_TLS', True)
EMAIL_USE_SSL = env_bool('EMAIL_USE_SSL', False)
DEFAULT_FROM_EMAIL = os.getenv('DEFAULT_FROM_EMAIL', os.getenv('DEFAULT_FROM_MAIL', EMAIL_HOST_USER))

# Mailgun (optional)
# Used for sending notification emails via Mailgun HTTP API.
MAILGUN_API_KEY = os.getenv('MAILGUN_API_KEY', '').strip()
MAILGUN_DOMAIN = os.getenv('MAILGUN_DOMAIN', '').strip()
MAILGUN_API_BASE_URL = os.getenv('MAILGUN_API_BASE_URL', 'https://api.mailgun.net/v3').strip().rstrip('/')
MAILGUN_FROM_EMAIL = os.getenv('MAILGUN_FROM_EMAIL', DEFAULT_FROM_EMAIL or '').strip()

# Notification emails
# Disabled by default; enable with EMAIL_NOTIFICATIONS_ENABLED=1 and Mailgun config.
EMAIL_NOTIFICATIONS_ENABLED = os.getenv('EMAIL_NOTIFICATIONS_ENABLED', '0').strip().lower() in {'1', 'true', 'yes', 'on'}

# Firebase Cloud Messaging is opt-in so local/test environments do not need
# service-account credentials. Keep the credential file outside the checkout.
FIREBASE_PUSH_ENABLED = env_bool('FIREBASE_PUSH_ENABLED', False)
FIREBASE_PROJECT_ID = os.getenv('FIREBASE_PROJECT_ID', '').strip()
FIREBASE_SERVICE_ACCOUNT_FILE = os.getenv('FIREBASE_SERVICE_ACCOUNT_FILE', '').strip()
FIREBASE_SERVICE_ACCOUNT_JSON = os.getenv('FIREBASE_SERVICE_ACCOUNT_JSON', '').strip()

# Requests to scheduler-only endpoints must provide this value in
# X-Padlupp-Cron-Secret. Development may omit it while DJANGO_DEBUG is enabled.
CRON_SHARED_SECRET = os.getenv('CRON_SHARED_SECRET', '').strip()

# SMS SETTINGS
SENDER_ID = os.getenv('SMS_SENDER_ID') # 11 characters max
ARKESEL_API_KEY = os.getenv('ARKESEL_SMS_API_KEY')

# DRF Spectacular settings
SPECTACULAR_SETTINGS = {
    'TITLE': 'PADLUPP API',
    'DESCRIPTION': 'PADLUPP API',
    'VERSION': '1.0.0',
    'SERVE_INCLUDE_SCHEMA': False,
}


# Google Sign-In
# Used to validate the `aud` claim on incoming Google `id_token`s.
GOOGLE_OAUTH2_CLIENT_ID = os.getenv('GOOGLE_OAUTH2_CLIENT_ID', '')

# Temporary beta gating: only allow waitlisters to sign up/sign in.
# Set env var BETA_WAITLIST_ONLY=0 to disable.
BETA_WAITLIST_ONLY = os.getenv('BETA_WAITLIST_ONLY', '1').strip().lower() not in {'0', 'false', 'no', 'off'}

# Use BigAutoField for implicit primary keys (keeps migrations stable).
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

