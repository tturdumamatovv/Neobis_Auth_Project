# Generated by Django 3.2 on 2023-06-07 17:03

import datetime
from django.db import migrations, models
from django.utils.timezone import utc


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0010_alter_user_date_born'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='date_born',
            field=models.DateField(default=datetime.datetime(2023, 6, 7, 17, 3, 4, 317770, tzinfo=utc)),
        ),
        migrations.AlterField(
            model_name='user',
            name='phone',
            field=models.CharField(blank=True, max_length=255, null=True, unique=True),
        ),
    ]
