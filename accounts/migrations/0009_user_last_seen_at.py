from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0008_user_notify_on_new_match_user_notify_on_new_message_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='last_seen_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
