# Generated by Django 2.1.5 on 2019-02-07 12:42

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('brandapp', '0016_ticketsetting_status'),
    ]

    operations = [
        migrations.AlterField(
            model_name='ticketsetting',
            name='status',
            field=models.TextField(blank=True, default='null', max_length=1000),
        ),
    ]