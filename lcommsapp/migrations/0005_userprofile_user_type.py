# Generated by Django 3.2.5 on 2022-03-08 04:40

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('lcommsapp', '0004_alter_userprofile_user'),
    ]

    operations = [
        migrations.AddField(
            model_name='userprofile',
            name='user_type',
            field=models.IntegerField(default=1),
        ),
    ]
