# Generated by Django 4.2.6 on 2023-11-05 08:47

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('coderapp', '0018_alter_post_category'),
    ]

    operations = [
        migrations.RenameField(
            model_name='post',
            old_name='blog_post',
            new_name='code_post',
        ),
    ]
