#!/usr/bin/env python3
"""Create production runtime environment files without storing secrets in git."""

from __future__ import annotations

import os
import pwd
import re
import secrets
from pathlib import Path


SOURCE_ENV = Path('/padlupp/padluppcore/padluppcore/.env')
APP_ENV = Path('/etc/padluppcore/app.env')
CRON_ENV = Path('/etc/padluppcore/cron.env')
KEY_PATTERN = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*)=')


def existing_value(lines: list[str], key: str) -> str | None:
    prefix = f'{key}='
    for line in lines:
        if line.startswith(prefix):
            return line[len(prefix):].strip().strip('"\'')
    return None


def main() -> None:
    if os.geteuid() != 0:
        raise SystemExit('Run this script as root.')

    app_group_id = pwd.getpwnam('padlupp-app').pw_gid
    APP_ENV.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    os.chown(APP_ENV.parent, 0, app_group_id)

    source = APP_ENV if APP_ENV.exists() else SOURCE_ENV
    lines = source.read_text(encoding='utf-8').splitlines() if source.exists() else []
    django_secret = existing_value(lines, 'DJANGO_SECRET_KEY') or secrets.token_urlsafe(48)
    cron_secret = existing_value(lines, 'CRON_SHARED_SECRET') or secrets.token_urlsafe(48)
    managed = {
        'DJANGO_SECRET_KEY': django_secret,
        'DJANGO_DEBUG': '0',
        'DJANGO_ALLOWED_HOSTS': 'api.padlupp.com,127.0.0.1',
        'DJANGO_CORS_ALLOWED_ORIGINS': 'https://app.padlupp.com',
        'DJANGO_CSRF_TRUSTED_ORIGINS': 'https://api.padlupp.com',
        'DATABASE_PATH': '/var/lib/padlupp/db.sqlite3',
        'MEDIA_ROOT': '/var/lib/padlupp/assets',
        'PUBLIC_BASE_URL': 'https://api.padlupp.com',
        'PADLUPP_APP_URL': 'https://app.padlupp.com',
        'CRON_SHARED_SECRET': cron_secret,
    }

    unmanaged_lines = [
        line
        for line in lines
        if not (match := KEY_PATTERN.match(line)) or match.group(1) not in managed
    ]
    rendered = unmanaged_lines + [''] + [f'{key}={value}' for key, value in managed.items()]
    APP_ENV.write_text('\n'.join(rendered).strip() + '\n', encoding='utf-8')
    os.chown(APP_ENV, 0, app_group_id)
    APP_ENV.chmod(0o640)

    CRON_ENV.write_text(f'CRON_SHARED_SECRET={cron_secret}\n', encoding='utf-8')
    os.chown(CRON_ENV, 0, 0)
    CRON_ENV.chmod(0o600)


if __name__ == '__main__':
    main()
