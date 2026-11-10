#!/usr/bin/env python3
"""Report only non-secret storage settings using the candidate application's code."""

import json
import os
import sys

sys.path.insert(0, os.getcwd())
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "padluppcore.settings")

import django

django.setup()
from django.conf import settings
from django.db import connection

connection.ensure_connection()
print(json.dumps({
    "debug": settings.DEBUG,
    "engine": connection.vendor,
    "database": connection.settings_dict["NAME"],
    "media": str(settings.MEDIA_ROOT.resolve()),
    "private_media": str(settings.PRIVATE_MEDIA_ROOT.resolve()),
}))
