from django.db import models

# Create your models here.
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin

from padluppcore.utils.models import TimeStampedModel
from .manager import AccountManager


class User(AbstractBaseUser, PermissionsMixin, TimeStampedModel):
    '''Custom User model for the application'''
    email = models.EmailField(max_length=50, unique=True)
    phone = models.CharField(max_length=15, unique=True)
    name = models.CharField(max_length=255)
    avatar = models.ImageField(upload_to='avatars/', blank=True, null=True)

    deleted = models.BooleanField(default=False)  # Soft delete

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    phone_verified = models.BooleanField(default=False)
    email_verified = models.BooleanField(default=False)

    # preferences
    preferred_notification_email = models.EmailField(max_length=50, blank=True, null=True)
    preferred_notification_phone = models.CharField(max_length=15, blank=True, null=True)

    objects = AccountManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['phone', 'name']