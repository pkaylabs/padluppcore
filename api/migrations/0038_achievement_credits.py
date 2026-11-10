from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ('api', '0037_community_checkin_schedule'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name='useraward', name='claimed_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.CreateModel(
            name='AchievementCredit',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('kind', models.CharField(max_length=40)),
                ('subject_type', models.CharField(max_length=20)),
                ('subject_id', models.CharField(max_length=100)),
                ('occurred_at', models.DateTimeField()),
                ('metadata', models.JSONField(default=dict)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='achievement_credits', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'indexes': [models.Index(fields=['user', 'kind'], name='achievement_user_kind_idx')],
                'constraints': [models.UniqueConstraint(fields=('user', 'kind', 'subject_type', 'subject_id'), name='uniq_achievement_credit_subject')],
            },
        ),
    ]
