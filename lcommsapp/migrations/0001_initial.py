# Generated by Django 3.2.5 on 2022-03-07 01:53

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='UserProfile',
            fields=[
                ('id', models.BigAutoField(auto_created=True,
                 primary_key=True, serialize=False, verbose_name='ID')),
                ('contact', models.CharField(max_length=250)),
                ('middle_name', models.CharField(max_length=250)),
                ('dob', models.DateField(blank=True, null=True)),
                ('address', models.TextField(blank=True, null=True)),
                ('image_path', models.TextField(blank=True, null=True)),
                ('user', models.OneToOneField(
                    on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
