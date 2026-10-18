"""Normalized chat interactions and non-public message/evidence storage."""

import os
import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.files.storage import FileSystemStorage
from django.db import models
from django.utils.deconstruct import deconstructible

from padluppcore.utils.models import TimeStampedModel


@deconstructible
class ProtectedMediaStorage(FileSystemStorage):
    @property
    def base_location(self):
        return getattr(settings, 'PRIVATE_MEDIA_ROOT', settings.BASE_DIR.parent / 'padlupp-private-media')

    @property
    def location(self):
        return os.path.abspath(self.base_location)

    def url(self, name):
        raise ValueError('Protected files must be read through an authenticated endpoint.')


protected_storage = ProtectedMediaStorage()


def protected_message_path(instance, filename):
    extension = os.path.splitext(filename)[1].lower()[:16]
    return f'chat_attachments/{uuid.uuid4().hex}{extension}'


def protected_evidence_path(instance, filename):
    extension = os.path.splitext(filename)[1].lower()[:16]
    return f'checkin_evidence/{uuid.uuid4().hex}{extension}'


class MessageHidden(TimeStampedModel):
    message = models.ForeignKey('api.Message', on_delete=models.CASCADE, related_name='hidden_for')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='hidden_messages')

    class Meta:
        constraints = [models.UniqueConstraint(fields=['message', 'user'], name='uniq_hidden_message_user')]


class MessageReaction(TimeStampedModel):
    message = models.ForeignKey('api.Message', on_delete=models.CASCADE, related_name='reactions')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='message_reactions')
    emoji = models.CharField(max_length=32)

    class Meta:
        constraints = [models.UniqueConstraint(fields=['message', 'user', 'emoji'], name='uniq_message_user_emoji')]


class MessagePin(TimeStampedModel):
    message = models.OneToOneField('api.Message', on_delete=models.CASCADE, related_name='pin')
    pinned_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)


class MessagePoll(TimeStampedModel):
    message = models.OneToOneField('api.Message', on_delete=models.CASCADE, related_name='poll')
    question = models.CharField(max_length=500)
    multiple_answers = models.BooleanField(default=False)


class MessagePollOption(TimeStampedModel):
    poll = models.ForeignKey(MessagePoll, on_delete=models.CASCADE, related_name='options')
    text = models.CharField(max_length=255)
    position = models.PositiveSmallIntegerField(default=0)

    class Meta:
        ordering = ['position', 'id']


class MessagePollVote(TimeStampedModel):
    option = models.ForeignKey(MessagePollOption, on_delete=models.CASCADE, related_name='votes')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='poll_votes')

    class Meta:
        constraints = [models.UniqueConstraint(fields=['option', 'user'], name='uniq_poll_option_user')]


class RetainedMessageAttachment(TimeStampedModel):
    """Evidence hold for an unresolved report, never an ordinary chat resource."""

    message = models.OneToOneField('api.Message', on_delete=models.CASCADE, related_name='retained_attachment')
    file = models.FileField(storage=protected_storage, upload_to='moderation_evidence/')
    filename = models.CharField(max_length=255, blank=True)
    mime = models.CharField(max_length=100, blank=True)


class RetainedMessageEvidence(TimeStampedModel):
    """Immutable reported target captured before destructive message deletion."""

    message = models.OneToOneField('api.Message', on_delete=models.PROTECT, related_name='retained_evidence')
    snapshot = models.JSONField()

    def save(self, *args, **kwargs):
        if not self._state.adding or (self.pk and type(self).objects.filter(pk=self.pk).exists()):
            raise ValidationError('Retained report evidence cannot be changed.')
        return super().save(*args, **kwargs)
