"""Fail-closed, additive-only policy for an automatic forward migration plan.

This inspects Django operation objects without executing them or accessing a
database. It is not a sandbox for untrusted migration code, or a guarantee of
application-level compatibility. Deployments must use an immutable checkout and
serialize migration execution; a code rollback must not reverse the schema.
"""

from dataclasses import dataclass
from typing import Iterable

from django.db import migrations


@dataclass(frozen=True)
class MigrationPolicyViolation:
    migration: str
    operation: str
    code: str
    reason: str
    operation_index: int | None = None


def migration_plan_violations(
    plan: Iterable[tuple[migrations.Migration, bool]],
) -> list[MigrationPolicyViolation]:
    """Return every policy violation; only exact, built-in operations pass."""
    violations = []
    for migration, backwards in plan:
        label = f'{migration.app_label}.{migration.name}'
        if backwards:
            violations.append(MigrationPolicyViolation(
                migration=label,
                operation='(migration)',
                code='reverse_migration',
                reason='Reverse migrations are never automatic.',
            ))
        if migration.operations and migration.atomic is not True:
            violations.append(MigrationPolicyViolation(
                migration=label,
                operation='(migration)',
                code='non_atomic_migration',
                reason='Migrations with operations must be atomic.',
            ))
        for index, operation in enumerate(migration.operations, start=1):
            operation_type = type(operation)
            # Subclasses may override database_forwards(), so are not allowlisted.
            if operation_type in (migrations.CreateModel, migrations.AddIndex):
                continue
            if operation_type is migrations.AddField:
                field = operation.field
                # A Python default (even preserve_default=True) does not protect
                # inserts from old code. db_default persists independently of it.
                if field.null is True or field.has_db_default() is True:
                    continue
                code = 'unsafe_add_field'
                reason = (
                    'AddField requires null=True or a persistent db_default; '
                    'a Python default is not sufficient for old-code inserts.'
                )
            else:
                code = 'operation_not_allowed'
                reason = 'Operation is outside the automatic migration allowlist.'
            violations.append(MigrationPolicyViolation(
                migration=label,
                operation=operation_type.__name__,
                operation_index=index,
                code=code,
                reason=reason,
            ))
    return violations
