# Generated by Django 3.2 on 2023-06-07 16:51

import datetime
from django.db import migrations, models
from django.utils.timezone import utc


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0009_auto_20230607_1604'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='date_born',
            field=models.DateField(default=datetime.datetime(2023, 6, 7, 16, 51, 4, 23696, tzinfo=utc)),
        ),
    ]
