# Generated by Django 3.2.5 on 2022-03-09 01:44

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('coderapp', '0009_post_banner'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userprofile',
            name='user_type',
            field=models.IntegerField(default=2),
        ),
    ]
