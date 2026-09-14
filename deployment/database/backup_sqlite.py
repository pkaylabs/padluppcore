#!/usr/bin/env python3
"""Create and validate a consistent SQLite backup."""

from __future__ import annotations

import argparse
import hashlib
import os
import sqlite3
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as database_file:
        for chunk in iter(lambda: database_file.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('source', type=Path)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()

    source = args.source.resolve(strict=True)
    destination = args.destination.resolve()
    if destination.exists():
        parser.error(f'destination already exists: {destination}')
    if source == destination:
        parser.error('source and destination must differ')

    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with sqlite3.connect(source) as source_database:
            with sqlite3.connect(destination) as backup_database:
                source_database.backup(backup_database)
                integrity = backup_database.execute('PRAGMA integrity_check').fetchall()
                if integrity != [('ok',)]:
                    raise RuntimeError(f'SQLite integrity check failed: {integrity}')
        os.chmod(destination, 0o600)
    except BaseException:
        destination.unlink(missing_ok=True)
        raise

    print(
        f'Backup verified: {destination} '
        f'({destination.stat().st_size} bytes, sha256={sha256(destination)})'
    )
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
