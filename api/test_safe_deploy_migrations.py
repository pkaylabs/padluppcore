import json
from io import StringIO
from unittest.mock import MagicMock, patch

from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import DatabaseError, migrations, models
from django.db.migrations.operations.base import Operation
from django.test import SimpleTestCase

from deployment.automatic.migration_policy import migration_plan_violations


def migration(*operations, name='0002_additive', atomic=True):
    result = migrations.Migration(name, 'api')
    result.operations = list(operations)
    result.atomic = atomic
    return result


def nullable_field():
    return migrations.AddField('example', 'note', models.TextField(null=True))


class MigrationPolicyTests(SimpleTestCase):
    def test_empty_plan_and_empty_merge_are_allowed(self):
        self.assertEqual(migration_plan_violations([]), [])
        for atomic in (True, False):
            with self.subTest(atomic=atomic):
                self.assertEqual(migration_plan_violations([(migration(atomic=atomic), False)]), [])

    def test_create_model_and_add_index_are_allowed(self):
        plan = [(migration(
            migrations.CreateModel('Example', [('id', models.BigAutoField(primary_key=True))]),
            migrations.AddIndex('example', models.Index(fields=['id'], name='example_id_idx')),
        ), False)]
        self.assertEqual(migration_plan_violations(plan), [])

    def test_nullable_additions_are_allowed_with_or_without_python_defaults(self):
        for field in (
            models.TextField(null=True),
            models.CharField(max_length=40, null=True, default='old-compatible'),
            models.IntegerField(null=True, db_default=None),
        ):
            for preserve_default in (True, False):
                with self.subTest(field=field, preserve_default=preserve_default):
                    operation = migrations.AddField('example', 'value', field, preserve_default=preserve_default)
                    self.assertEqual(migration_plan_violations([(migration(operation), False)]), [])

    def test_persistent_database_default_is_allowed_including_without_python_default(self):
        for field in (
            models.IntegerField(db_default=0),
            models.CharField(max_length=40, db_default='ready', default='new-code'),
            models.DateTimeField(db_default=models.functions.Now()),
            models.TextField(null=True, db_default='optional'),
        ):
            for preserve_default in (True, False):
                with self.subTest(field=field, preserve_default=preserve_default):
                    operation = migrations.AddField('example', 'value', field, preserve_default=preserve_default)
                    self.assertEqual(migration_plan_violations([(migration(operation), False)]), [])

    def test_non_null_python_defaults_do_not_make_old_code_inserts_safe(self):
        for field in (
            models.TextField(),
            models.TextField(blank=True),
            models.TextField(default=''),
            models.IntegerField(default=0),
            models.BooleanField(default=False),
            models.JSONField(default=dict),
            models.TextField(default=None),
            models.DateTimeField(auto_now_add=True),
        ):
            for preserve_default in (True, False):
                with self.subTest(field=field, preserve_default=preserve_default):
                    operation = migrations.AddField('example', 'value', field, preserve_default=preserve_default)
                    violations = migration_plan_violations([(migration(operation), False)])
                    self.assertEqual(len(violations), 1)
                    self.assertEqual(violations[0].code, 'unsafe_add_field')
                    self.assertEqual(violations[0].operation, 'AddField')

    def test_every_other_builtin_operation_is_denied_including_noop_and_state_only(self):
        constraint = models.CheckConstraint(condition=models.Q(id__gt=0), name='positive_id')
        operations = [
            migrations.DeleteModel('Example'),
            migrations.RemoveField('example', 'value'),
            migrations.AlterField('example', 'value', models.TextField(null=True)),
            migrations.RenameModel('Example', 'Replacement'),
            migrations.RenameField('example', 'value', 'renamed'),
            migrations.RenameIndex('example', 'new_idx', old_name='old_idx'),
            migrations.RemoveIndex('example', 'old_idx'),
            migrations.AddConstraint('example', constraint),
            migrations.RemoveConstraint('example', 'positive_id'),
            migrations.AlterConstraint('example', 'positive_id', constraint),
            migrations.AlterModelTable('Example', 'another_table'),
            migrations.AlterModelTableComment('Example', 'A comment'),
            migrations.AlterModelOptions('Example', {'ordering': ['id']}),
            migrations.AlterModelManagers('Example', []),
            migrations.AlterOrderWithRespectTo('Example', 'parent'),
            migrations.AlterIndexTogether('Example', {('id', 'value')}),
            migrations.AlterUniqueTogether('Example', {('id', 'value')}),
            migrations.RunPython(migrations.RunPython.noop),
            migrations.RunSQL(migrations.RunSQL.noop),
            migrations.SeparateDatabaseAndState(),
            migrations.SeparateDatabaseAndState(
                database_operations=[nullable_field()], state_operations=[nullable_field()],
            ),
        ]
        for operation in operations:
            with self.subTest(operation=type(operation).__name__):
                violations = migration_plan_violations([(migration(operation), False)])
                self.assertEqual(len(violations), 1)
                self.assertEqual(violations[0].code, 'operation_not_allowed')
                self.assertEqual(violations[0].operation, type(operation).__name__)

    def test_unknown_operations_and_subclasses_cannot_bypass_allowlist(self):
        class CustomOperation(Operation):
            pass

        class CustomCreate(migrations.CreateModel):
            pass

        class CustomIndex(migrations.AddIndex):
            pass

        class CustomAdd(migrations.AddField):
            pass

        for operation in (
            CustomOperation(),
            CustomCreate('Example', []),
            CustomIndex('example', models.Index(fields=['id'], name='example_idx')),
            CustomAdd('example', 'value', models.TextField(null=True)),
        ):
            with self.subTest(operation=type(operation).__name__):
                violations = migration_plan_violations([(migration(operation), False)])
                self.assertEqual(violations[0].code, 'operation_not_allowed')

    def test_non_atomic_migration_with_actual_operations_is_denied(self):
        for operation in (
            nullable_field(),
            migrations.CreateModel('Example', []),
            migrations.AddIndex('example', models.Index(fields=['id'], name='example_idx')),
            migrations.RunPython(migrations.RunPython.noop),
        ):
            with self.subTest(operation=type(operation).__name__):
                violations = migration_plan_violations([(migration(operation, atomic=False), False)])
                self.assertEqual(violations[0].code, 'non_atomic_migration')

    def test_reverse_plan_is_denied_even_for_empty_merge_or_allowed_operations(self):
        for item in (migration(), migration(nullable_field())):
            with self.subTest(operations=len(item.operations)):
                violations = migration_plan_violations([(item, True)])
                self.assertEqual(len(violations), 1)
                self.assertEqual(violations[0].code, 'reverse_migration')

    def test_mixed_direction_plan_is_denied_and_all_failures_are_identified(self):
        plan = [
            (migration(nullable_field(), name='0002_safe'), False),
            (migration(migrations.RemoveField('example', 'value'), name='0003_unsafe', atomic=False), True),
            (migration(migrations.DeleteModel('Example'), name='0004_unsafe'), False),
        ]
        violations = migration_plan_violations(iter(plan))
        self.assertEqual([item.code for item in violations], [
            'reverse_migration', 'non_atomic_migration', 'operation_not_allowed', 'operation_not_allowed',
        ])
        self.assertEqual(violations[2].migration, 'api.0003_unsafe')
        self.assertEqual(violations[2].operation_index, 1)
        self.assertEqual(violations[3].migration, 'api.0004_unsafe')

    def test_policy_is_pure_and_does_not_evaluate_python_defaults(self):
        default = MagicMock(side_effect=AssertionError('must not evaluate defaults'))
        operation = migrations.AddField('example', 'value', models.JSONField(default=default))
        original = migration(operation)
        self.assertEqual(migration_plan_violations([(original, False)])[0].code, 'unsafe_add_field')
        self.assertIs(original.operations[0], operation)
        default.assert_not_called()


class SafeDeployMigrateCommandTests(SimpleTestCase):
    command_module = 'api.management.commands.safe_deploy_migrate'

    def setUp(self):
        self.stdout = StringIO()
        self.stderr = StringIO()
        connection_patch = patch(f'{self.command_module}.connection')
        self.connection = connection_patch.start()
        self.addCleanup(connection_patch.stop)
        self.connection.vendor = 'postgresql'
        self.connection.settings_dict = {'NAME': 'padlupp'}
        self.cursor = self.connection.cursor.return_value.__enter__.return_value
        self.cursor.fetchone.return_value = ('padlupp',)

        executor_patch = patch(f'{self.command_module}.MigrationExecutor')
        self.executor_type = executor_patch.start()
        self.addCleanup(executor_patch.stop)
        self.executor = self.executor_type.return_value
        self.executor.loader.detect_conflicts.return_value = {}
        self.targets = [('api', '0002_additive'), ('accounts', '0001_initial')]
        self.executor.loader.graph.leaf_nodes.return_value = self.targets
        self.plan = [(migration(nullable_field()), False)]
        self.executor.migration_plan.return_value = self.plan

        apply_patch = patch(f'{self.command_module}.call_command')
        self.apply = apply_patch.start()
        self.addCleanup(apply_patch.stop)

    def run_command(self, *args, **kwargs):
        return call_command('safe_deploy_migrate', *args, stdout=self.stdout, stderr=self.stderr, **kwargs)

    def assert_blocked(self, *args, **kwargs):
        with self.assertRaisesMessage(CommandError, 'manual review needed'):
            self.run_command(*args, **kwargs)
        self.apply.assert_not_called()
        self.executor.migrate.assert_not_called()

    def test_default_preflight_reads_identity_and_pending_leaf_plan_but_never_applies(self):
        self.run_command()
        self.cursor.execute.assert_called_once_with('SELECT current_database()')
        self.executor_type.assert_called_once_with(self.connection)
        self.executor.loader.check_consistent_history.assert_called_once_with(self.connection)
        self.executor.loader.graph.leaf_nodes.assert_called_once_with()
        self.executor.migration_plan.assert_called_once_with(self.targets)
        self.apply.assert_not_called()
        self.executor.migrate.assert_not_called()
        self.assertIn('ALLOWED: Preflight passed; no migrations were applied.', self.stdout.getvalue())

    def test_apply_is_noninteractive_and_only_after_identity_and_policy_guards(self):
        events = []
        self.cursor.execute.side_effect = lambda *_: events.append('identity')
        self.executor.migration_plan.side_effect = lambda *_: events.append('plan') or self.plan
        self.apply.side_effect = lambda *_, **__: events.append('apply')
        self.run_command('--apply')
        self.assertEqual(events, ['identity', 'plan', 'apply'])
        self.apply.assert_called_once()
        args, options = self.apply.call_args
        self.assertEqual(args, ('migrate',))
        self.assertEqual(options['database'], 'default')
        for name in ('interactive', 'fake', 'fake_initial', 'run_syncdb', 'prune', 'skip_checks'):
            self.assertIs(options[name], False, name)
        self.assertIn('APPLIED', self.stdout.getvalue())

    def test_all_blocked_plans_never_call_migrate_even_with_apply(self):
        for plan in (
            [(migration(migrations.DeleteModel('Example')), False)],
            [(migration(migrations.AddField('example', 'value', models.TextField(default='new'))), False)],
            [(migration(nullable_field(), atomic=False), False)],
            [(migration(nullable_field()), True)],
        ):
            for apply in (False, True):
                with self.subTest(plan=plan, apply=apply):
                    self.executor.migration_plan.return_value = plan
                    self.assert_blocked(apply=apply)

    def test_blocked_text_names_migration_and_operation_without_sql_or_defaults(self):
        secret = 'not-for-deployment-logs'
        self.executor.migration_plan.return_value = [(migration(
            nullable_field(), migrations.RunSQL(f'SELECT \'{secret}\''),
            migrations.AddField('example', 'value', models.TextField(default=secret)),
            name='0003_manual',
        ), False)]
        self.assert_blocked('--apply')
        output = self.stdout.getvalue() + self.stderr.getvalue()
        self.assertIn('api.0003_manual operation #2 RunSQL', output)
        self.assertIn('api.0003_manual operation #3 AddField', output)
        self.assertIn('Manual review needed', output)
        self.assertNotIn(secret, output)

    def test_vendor_guard_runs_before_connection_planning_or_mutation(self):
        for vendor in ('sqlite', 'mysql', 'oracle', 'unknown'):
            with self.subTest(vendor=vendor):
                self.connection.vendor = vendor
                self.assert_blocked('--apply')
                self.connection.cursor.assert_not_called()
                self.executor_type.assert_not_called()

    def test_configured_database_name_guard_runs_before_connection_or_mutation(self):
        for name in ('wrong-db', '', None):
            with self.subTest(name=name):
                self.connection.settings_dict['NAME'] = name
                self.assert_blocked('--apply')
                self.connection.cursor.assert_not_called()
                self.executor_type.assert_not_called()

    def test_blank_expected_database_name_cannot_disable_guard(self):
        for name in ('', '   '):
            with self.subTest(name=name):
                self.assert_blocked('--apply', database_name=name)
                self.connection.cursor.assert_not_called()
                self.executor_type.assert_not_called()

    def test_actual_database_identity_must_also_match_before_planning_or_mutation(self):
        self.cursor.fetchone.return_value = ('unexpected-service-database',)
        self.assert_blocked('--apply')
        self.executor_type.assert_not_called()
        self.assertNotIn('unexpected-service-database', self.stdout.getvalue())

    def test_explicit_ephemeral_database_name_is_allowed_but_still_must_match(self):
        name = 'test_padlupp_safe_deploy_ci'
        self.connection.settings_dict['NAME'] = name
        self.cursor.fetchone.return_value = (name,)
        self.assert_blocked('--apply')
        self.run_command('--apply', '--database-name', name)
        self.apply.assert_called_once()

    def test_connection_or_planning_failure_is_sanitized_and_never_applies(self):
        secret = 'password=not-for-deployment-logs'
        for target in (
            self.connection.cursor,
            self.executor_type,
            self.executor.loader.check_consistent_history,
            self.executor.loader.detect_conflicts,
            self.executor.loader.graph.leaf_nodes,
            self.executor.migration_plan,
        ):
            with self.subTest(target=target):
                target.side_effect = DatabaseError(secret)
                try:
                    self.assert_blocked('--apply')
                finally:
                    target.side_effect = None
        self.assertNotIn(secret, self.stdout.getvalue() + self.stderr.getvalue())

    def test_conflicting_branches_block_before_plan_or_apply(self):
        self.executor.loader.detect_conflicts.return_value = {'api': ['0002_a', '0002_b']}
        self.assert_blocked('--apply')
        self.executor.migration_plan.assert_not_called()
        self.assertIn('Conflicting migration branches', self.stdout.getvalue())

    def test_json_preflight_is_one_structured_result(self):
        self.run_command('--json')
        result = json.loads(self.stdout.getvalue())
        self.assertEqual(result['status'], 'allowed')
        self.assertEqual(result['mode'], 'preflight')
        self.assertEqual(result['pending_migrations'], ['api.0002_additive'])
        self.assertEqual(result['violations'], [])
        self.apply.assert_not_called()

    def test_json_policy_block_identifies_operation_without_sensitive_values(self):
        self.executor.migration_plan.return_value = [(migration(
            migrations.RunSQL("DELETE FROM example WHERE token = 'secret-value'"),
        ), False)]
        self.assert_blocked('--json', '--apply')
        result = json.loads(self.stdout.getvalue())
        self.assertEqual(result['status'], 'blocked')
        self.assertEqual(result['code'], 'migration_policy')
        self.assertEqual(result['violations'][0]['migration'], 'api.0002_additive')
        self.assertEqual(result['violations'][0]['operation'], 'RunSQL')
        self.assertEqual(result['violations'][0]['operation_index'], 1)
        self.assertNotIn('secret-value', self.stdout.getvalue())

    def test_json_apply_captures_nested_django_output(self):
        def migrate(*args, **options):
            options['stdout'].write('Django progress output')
            options['stderr'].write('Django diagnostic output')

        self.apply.side_effect = migrate
        self.run_command('--apply', '--json')
        result = json.loads(self.stdout.getvalue())
        self.assertEqual(result['status'], 'applied')
        self.assertEqual(self.stderr.getvalue(), '')
        self.assertNotIn('Django progress output', self.stdout.getvalue())

    def test_apply_failure_does_not_reverse_or_claim_nothing_was_applied(self):
        self.apply.side_effect = DatabaseError('password=not-for-deployment-logs')
        with self.assertRaisesMessage(CommandError, 'migration failed'):
            self.run_command('--apply', '--json')
        self.apply.assert_called_once()
        result = json.loads(self.stdout.getvalue())
        self.assertEqual(result['status'], 'failed')
        self.assertIn('Some forward migrations may already be applied', result['message'])
        self.assertIn('No automatic reversal', result['message'])
        self.assertNotIn('not-for-deployment-logs', self.stdout.getvalue())

    def test_empty_plan_is_a_read_only_success_by_default(self):
        self.executor.migration_plan.return_value = []
        self.run_command('--json')
        self.assertEqual(json.loads(self.stdout.getvalue())['pending_migrations'], [])
        self.apply.assert_not_called()

    def test_dangerous_or_targeted_options_are_not_exposed(self):
        for option in ('fake', 'fake_initial', 'run_syncdb', 'prune', 'app_label', 'migration_name', 'database'):
            with self.subTest(option=option):
                with self.assertRaises(TypeError):
                    self.run_command(**{option: True})
        for args in (('--fake',), ('--fake-initial',), ('--run-syncdb',), ('--prune',), ('api', 'zero')):
            with self.subTest(args=args):
                with self.assertRaises(CommandError):
                    self.run_command(*args)
        self.apply.assert_not_called()
        self.executor_type.assert_not_called()
