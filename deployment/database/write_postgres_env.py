#!/usr/bin/env python3
"""Write PostgreSQL settings to a Django environment file atomically."""

from __future__ import annotations

import argparse
import os
import tempfile
from pathlib import Path


MANAGED_KEYS = {
    'DATABASE_ENGINE',
    'POSTGRES_DB',
    'POSTGRES_USER',
    'POSTGRES_PASSWORD',
    'POSTGRES_HOST',
    'POSTGRES_PORT',
    'POSTGRES_SSLMODE',
    'DATABASE_CONN_MAX_AGE',
}


def setting_name(line: str) -> str | None:
    stripped = line.strip()
    if not stripped or stripped.startswith('#') or '=' not in stripped:
        return None
    return stripped.split('=', 1)[0].strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('source', type=Path)
    parser.add_argument('destination', type=Path)
    parser.add_argument('database')
    parser.add_argument('password_file', type=Path)
    parser.add_argument('--user', default='padlupp_app')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', default='5432')
    parser.add_argument('--sslmode', default='prefer')
    parser.add_argument('--connection-max-age', default='60')
    args = parser.parse_args()

    source = args.source.resolve(strict=True)
    destination = args.destination.resolve()
    password = args.password_file.read_text(encoding='utf-8').strip()
    if not password or '\n' in password or '\r' in password:
        parser.error('password file must contain one non-empty line')

    source_stat = source.stat()
    retained_lines = [
        line
        for line in source.read_text(encoding='utf-8').splitlines()
        if setting_name(line) not in MANAGED_KEYS
    ]
    while retained_lines and not retained_lines[-1]:
        retained_lines.pop()
    retained_lines.extend(
        [
            '',
            '# Database configuration',
            'DATABASE_ENGINE=postgresql',
            f'POSTGRES_DB={args.database}',
            f'POSTGRES_USER={args.user}',
            f'POSTGRES_PASSWORD={password}',
            f'POSTGRES_HOST={args.host}',
            f'POSTGRES_PORT={args.port}',
            f'POSTGRES_SSLMODE={args.sslmode}',
            f'DATABASE_CONN_MAX_AGE={args.connection_max_age}',
        ]
    )

    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode='w',
            encoding='utf-8',
            dir=destination.parent,
            prefix=f'.{destination.name}.',
            delete=False,
        ) as temporary_file:
            temporary_file.write('\n'.join(retained_lines) + '\n')
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
            temporary_path = Path(temporary_file.name)
        os.chmod(temporary_path, source_stat.st_mode & 0o777)
        if hasattr(os, 'chown'):
            os.chown(temporary_path, source_stat.st_uid, source_stat.st_gid)
        os.replace(temporary_path, destination)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)

    print(f'PostgreSQL environment written atomically: {destination}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
