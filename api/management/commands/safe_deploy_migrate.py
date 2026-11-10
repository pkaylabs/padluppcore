"""Preflight by default; apply only an additive, forward PostgreSQL plan."""

import json
from dataclasses import asdict
from io import StringIO

from django.core.management import call_command
from django.core.management.base import BaseCommand, CommandError
from django.db import DEFAULT_DB_ALIAS, connection
from django.db.migrations.executor import MigrationExecutor

from deployment.automatic.migration_policy import migration_plan_violations


class Command(BaseCommand):
    help = (
        'Check the pending default-database migration plan without writes. '
        'Use --apply to run approved forward migrations noninteractively.'
    )
    # No implicit database work may precede the explicit identity/policy guards.
    requires_system_checks = []
    requires_migrations_checks = False

    def add_arguments(self, parser):
        parser.add_argument('--apply', action='store_true', help='Apply only after all guards pass.')
        parser.add_argument(
            '--database-name', default='padlupp',
            help='Required PostgreSQL database name (default: padlupp).',
        )
        parser.add_argument('--json', action='store_true', help='Emit a JSON result instead of text.')

    def _report(self, options, status, message, *, code=None, plan=(), violations=()):
        result = {
            'status': status,
            'mode': 'apply' if options['apply'] else 'preflight',
            'message': message,
            'pending_migrations': [f'{migration.app_label}.{migration.name}' for migration, _ in plan],
            'violations': [asdict(violation) for violation in violations],
        }
        if code is not None:
            result['code'] = code
        if options['json']:
            self.stdout.write(json.dumps(result, sort_keys=True))
        else:
            self.stdout.write(f'[SAFE_DEPLOY_MIGRATE] {status.upper()}: {message}')
            for violation in violations:
                position = f' operation #{violation.operation_index}' if violation.operation_index else ''
                self.stdout.write(
                    f'  {violation.migration}{position} {violation.operation}: '
                    f'{violation.reason} Manual review needed.'
                )

    def _block(self, options, code, message, *, plan=(), violations=()):
        self._report(
            options, 'blocked', f'{message} Manual review needed; no migrations were applied.',
            code=code, plan=plan, violations=violations,
        )
        raise CommandError('Automatic migration blocked; manual review needed.') from None

    def handle(self, *args, **options):
        expected_name = options['database_name']
        if not expected_name or not expected_name.strip():
            self._block(options, 'database_name_required', 'An expected database name is required.')
        if connection.vendor != 'postgresql':
            self._block(options, 'database_vendor', 'Only PostgreSQL is permitted.')
        if connection.settings_dict.get('NAME') != expected_name:
            self._block(options, 'database_name', 'Configured database does not match the expected name.')

        try:
            # Also verify the actual target, not just configuration (e.g. service
            # files or connection options may override the configured name).
            with connection.cursor() as cursor:
                cursor.execute('SELECT current_database()')
                actual_name = cursor.fetchone()[0]
        except Exception:
            self._block(options, 'database_identity', 'Could not verify the connected database identity.')
        if actual_name != expected_name:
            self._block(options, 'database_identity', 'Connected database does not match the expected name.')

        try:
            executor = MigrationExecutor(connection)
            executor.loader.check_consistent_history(connection)
            conflicts = executor.loader.detect_conflicts()
            if not conflicts:
                targets = executor.loader.graph.leaf_nodes()
                plan = executor.migration_plan(targets)
                violations = migration_plan_violations(plan)
        except Exception:
            # Connection and migration exceptions may contain credentials or SQL.
            self._block(options, 'migration_plan', 'Could not safely inspect the migration plan.')
        if conflicts:
            self._block(options, 'migration_conflicts', 'Conflicting migration branches must be resolved.')
        if violations:
            self._block(
                options, 'migration_policy', 'The pending plan is not approved for automatic deployment.',
                plan=plan, violations=violations,
            )
        if not options['apply']:
            self._report(
                options, 'allowed', 'Preflight passed; no migrations were applied. Use --apply to migrate.',
                plan=plan,
            )
            return

        # Never pass a target, fake, syncdb, prune, or reverse option through.
        # JSON mode captures Django's human-readable output so stdout stays JSON.
        output = StringIO() if options['json'] else self.stdout
        errors = StringIO() if options['json'] else self.stderr
        try:
            call_command(
                'migrate', database=DEFAULT_DB_ALIAS, interactive=False,
                fake=False, fake_initial=False, run_syncdb=False, prune=False,
                verbosity=options['verbosity'], stdout=output, stderr=errors,
                no_color=options['no_color'], force_color=options['force_color'],
                skip_checks=False,
            )
        except Exception:
            self._report(
                options, 'failed',
                'Migrate failed; manual review needed. Some forward migrations may already be applied. '
                'No automatic reversal was attempted.',
                code='migration_apply', plan=plan,
            )
            raise CommandError('Automatic migration failed; manual review needed.') from None
        self._report(options, 'applied', 'Approved forward migrations applied successfully.', plan=plan)
