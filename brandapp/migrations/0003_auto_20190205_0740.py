# Generated by Django 2.1.5 on 2019-02-05 07:40

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('brandapp', '0002_auto_20190205_0736'),
    ]

    operations = [
        migrations.AddField(
            model_name='ticketsetting',
            name='classifiation',
            field=models.TextField(blank=True, max_length=1000),
        ),
        migrations.AddField(
            model_name='ticketsetting',
            name='domain',
            field=models.TextField(blank=True, max_length=1000),
        ),
        migrations.AddField(
            model_name='ticketsetting',
            name='impact',
            field=models.TextField(blank=True, max_length=5000),
        ),
        migrations.AddField(
            model_name='ticketsetting',
            name='incident_details',
            field=models.TextField(blank=True, max_length=1000),
        ),
        migrations.AddField(
            model_name='ticketsetting',
            name='incident_id',
            field=models.TextField(blank=True, max_length=1000),
        ),
        migrations.AddField(
            model_name='ticketsetting',
            name='recom_action',
            field=models.TextField(blank=True, max_length=5000),
        ),
        migrations.AddField(
            model_name='ticketsetting',
            name='url',
            field=models.TextField(blank=True, max_length=1000),
        ),
    ]