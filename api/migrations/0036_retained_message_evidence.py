from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ('api', '0035_community_membership_feedback'),
    ]

    operations = [
        migrations.CreateModel(
            name='RetainedMessageEvidence',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('snapshot', models.JSONField()),
                ('message', models.OneToOneField(on_delete=django.db.models.deletion.PROTECT, related_name='retained_evidence', to='api.message')),
            ],
            options={'abstract': False},
        ),
    ]
