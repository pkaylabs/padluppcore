#!/usr/bin/env python3
"""Run as postgres; hold a consistent snapshot or count an isolated restore."""

import json
import re
import sys

import psycopg
from psycopg import sql


def counts(connection):
    tables = connection.execute(
        "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename"
    ).fetchall()
    return {
        table: connection.execute(
            sql.SQL("SELECT count(*) FROM public.{}").format(sql.Identifier(table))
        ).fetchone()[0]
        for (table,) in tables
    }


def main():
    mode = sys.argv[1]
    database = "padlupp" if mode == "hold" else sys.argv[2]
    if database != "padlupp" and not re.fullmatch(r"padlupp_verify_[a-f0-9]{12}", database):
        raise SystemExit("Unexpected verification database")
    with psycopg.connect(dbname=database) as connection:
        connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        if mode == "hold":
            snapshot = connection.execute("SELECT pg_export_snapshot()").fetchone()[0]
            print(json.dumps({"snapshot": snapshot, "counts": counts(connection)}), flush=True)
            sys.stdin.readline()
        elif mode == "counts":
            print(json.dumps(counts(connection)), flush=True)
        else:
            raise SystemExit("Unexpected snapshot operation")
        connection.rollback()


if __name__ == "__main__":
    main()
