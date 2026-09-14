# SQLite to PostgreSQL migration

Production migration uses a rehearsal database before cutover:

1. Create a consistent SQLite backup with Python's SQLite backup API.
2. Export application data with Django `dumpdata`, excluding generated content
   types and permissions.
3. Migrate and load a separate PostgreSQL rehearsal database.
4. Export PostgreSQL and compare both fixtures with `compare_fixtures.py`.
5. Stop the application briefly, repeat the backup/export/import verification,
   and only then update the production environment to PostgreSQL.
6. Keep the final SQLite backup and a PostgreSQL custom-format dump for rollback.

Suggested fixture command:

```bash
python manage.py dumpdata --all --natural-foreign --natural-primary \
  --exclude contenttypes.contenttype --exclude auth.permission --indent 2
```

Never switch `DATABASE_ENGINE` until the comparison exits successfully.
