# Generated by Django 2.1.5 on 2019-02-05 10:48

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('brandapp', '0006_remove_ticketsetting_classifiation'),
    ]

    operations = [
        migrations.AlterField(
            model_name='ticketsetting',
            name='pimage',
            field=models.CharField(blank=True, max_length=600),
        ),
    ]
