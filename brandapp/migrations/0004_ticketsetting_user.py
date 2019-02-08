# Generated by Django 2.1.5 on 2019-02-05 07:44

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('brandapp', '0003_auto_20190205_0740'),
    ]

    operations = [
        migrations.AddField(
            model_name='ticketsetting',
            name='user',
            field=models.ForeignKey(default=40, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
            preserve_default=False,
        ),
    ]
