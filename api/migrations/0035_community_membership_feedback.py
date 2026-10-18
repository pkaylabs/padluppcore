from django.db import migrations, models


class AddFieldIfMissing(migrations.AddField):
    """Preserve feedback already present in an interim 0033 QA schema."""

    def database_forwards(self, app_label, schema_editor, from_state, to_state):
        model = to_state.apps.get_model(app_label, self.model_name)
        if not self.allow_migrate_model(schema_editor.connection.alias, model):
            return
        with schema_editor.connection.cursor() as cursor:
            columns = schema_editor.connection.introspection.get_table_description(
                cursor, model._meta.db_table,
            )
        if model._meta.get_field(self.name).column not in {column.name for column in columns}:
            super().database_forwards(app_label, schema_editor, from_state, to_state)


class Migration(migrations.Migration):
    dependencies = [
        ('api', '0034_messaging_checkin_policy'),
    ]

    operations = [
        AddFieldIfMissing(
            model_name='communitymembership',
            name='feedback',
            field=models.TextField(blank=True),
        ),
        AddFieldIfMissing(
            model_name='communitytaskmembership',
            name='feedback',
            field=models.TextField(blank=True),
        ),
    ]
