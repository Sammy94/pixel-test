# Generated by Django 2.1.5 on 2019-02-05 10:47

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('brandapp', '0005_auto_20190205_0910'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='ticketsetting',
            name='classifiation',
        ),
    ]
