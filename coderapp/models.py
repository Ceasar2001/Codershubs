from unicodedata import category
from django.db import models
from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.models import User, Group

from django.dispatch import receiver
from django.db.models.signals import post_save
from django.forms import ValidationError
from django.utils import timezone


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    email_confirmed = models.BooleanField(default=False)
    middle_name = models.CharField(max_length=250, blank=True)
    avatar = models.ImageField(blank=True, null=True, upload_to='images/')
    user_type = models.IntegerField(default=2)

    def __str__(self):
        return self.user.username


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)


@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    print(instance)
    try:
        profile = UserProfile.objects.get(user=instance)
    except Exception as e:
        UserProfile.objects.create(user=instance)
    instance.profile.save()


class Category(models.Model):
    name = models.CharField(max_length=250)
    description = models.TextField(blank=True, null=True)
    status = models.IntegerField(default=1)
    date_added = models.DateTimeField(default=timezone.now)
    date_updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name


class Post(models.Model):
    category = models.ForeignKey(Category, on_delete=models.CASCADE)
    title = models.TextField()
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    
    banner = models.ImageField(blank=True, null=True, upload_to='images/')
    status = models.IntegerField(default=0)
    date_added = models.DateTimeField(default=timezone.now)
    date_updated = models.DateTimeField(auto_now=True)
    code_post = models.TextField()

    def __str__(self):
        return self.title + " - " + self.category.name

class ActivityLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    action = models.CharField(max_length=255)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.timestamp} - {self.user} - {self.action}"