from django.db import migrations, models
from django.db.models import F


def promote_existing_owners(apps, schema_editor):
    GoalMembership = apps.get_model('api', 'GoalMembership')
    GoalMembership.objects.filter(user_id=F('goal__user_id')).update(role='admin')


def demote_existing_owners(apps, schema_editor):
    GoalMembership = apps.get_model('api', 'GoalMembership')
    GoalMembership.objects.filter(user_id=F('goal__user_id')).update(role='member')


class Migration(migrations.Migration):
    dependencies = [
        ('api', '0031_referralinvite_useraward'),
    ]

    operations = [
        migrations.AddField(
            model_name='goalmembership',
            name='role',
            field=models.CharField(
                choices=[('member', 'Member'), ('admin', 'Admin')],
                default='member',
                max_length=16,
            ),
        ),
        migrations.RunPython(promote_existing_owners, demote_existing_owners),
    ]
