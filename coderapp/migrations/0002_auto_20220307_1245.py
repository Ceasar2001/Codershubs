# Generated by Django 3.2.5 on 2022-03-07 04:45

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('coderapp', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='userprofile',
            name='image_path',
        ),
        migrations.AddField(
            model_name='userprofile',
            name='avatar',
            field=models.ImageField(blank=True, null=True, upload_to=''),
        ),
    ]