from django.db import models
from django.conf import settings

# Create your models here.
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin

from padluppcore.utils.models import TimeStampedModel
from .manager import AccountManager


class User(AbstractBaseUser, PermissionsMixin, TimeStampedModel):
    '''Custom User model for the application'''
    email = models.EmailField(max_length=50, unique=True)
    phone = models.CharField(max_length=15, null=True, blank=True, unique=True)
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

    # notification preferences
    notify_on_new_message = models.BooleanField(default=True)
    notify_on_new_match = models.BooleanField(default=True)
    notify_on_reminders = models.BooleanField(default=True)

    objects = AccountManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['phone', 'name']


class AccountDeletionRequest(TimeStampedModel):
    """Represents a user's request to delete their account."""

    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='account_deletion_requests',
    )
    reason = models.TextField()


class PasswordResetOTP(TimeStampedModel):
    """OTP + reset token records for the forgot-password flow.

    Security notes:
    - OTP and reset token are stored hashed (never plaintext).
    - OTP can be used only once to mint a reset token.
    - Reset token can be used only once to reset the password.
    """

    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='password_reset_otps',
    )

    otp_hash = models.CharField(max_length=256)
    otp_expires_at = models.DateTimeField()
    otp_used_at = models.DateTimeField(null=True, blank=True)

    reset_token_hash = models.CharField(max_length=256, blank=True, default='')
    reset_token_expires_at = models.DateTimeField(null=True, blank=True)
    reset_token_used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['otp_expires_at']),
            models.Index(fields=['reset_token_expires_at']),
        ]