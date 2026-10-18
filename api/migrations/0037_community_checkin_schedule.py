from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('api', '0036_retained_message_evidence'),
    ]

    operations = [
        migrations.AddField(
            model_name='communitytask',
            name='checkin_schedule_effective_from',
            field=models.DateField(blank=True, null=True),
        ),
    ]
