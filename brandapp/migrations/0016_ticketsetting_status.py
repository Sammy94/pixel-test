# Generated by Django 2.1.5 on 2019-02-07 12:40

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('brandapp', '0015_remove_ticketsetting_status'),
    ]

    operations = [
        migrations.AddField(
            model_name='ticketsetting',
            name='status',
            field=models.TextField(blank=True, max_length=1000),
        ),
    ]
