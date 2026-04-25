from datetime import timedelta

from django.db.models import F, Max, Q
from django.db.models.functions import Coalesce
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.models import User
from padluppcore.utils.email import EmailSendError, send_mailgun_email

from .models import InactivityNudgeLog
from .nudges import build_inactivity_nudge_email


class InactiveUserNudgeView(APIView):
	"""Send nudges to users who have been inactive for a configurable threshold.

	This endpoint is intentionally unauthenticated so a cron job can call it directly.
	It is idempotent for a given user/inactivity span via InactivityNudgeLog.
	"""

	authentication_classes = []
	permission_classes = [AllowAny]

	def post(self, request):
		threshold_days = 14
		cutoff = timezone.now() - timedelta(days=threshold_days)

		users = (
			User.objects.filter(is_active=True, deleted=False)
			.exclude(Q(email__isnull=True) | Q(email=''))
			.annotate(latest_daily_activity_at=Max('daily_activities__last_activity_at'))
			.annotate(latest_activity_at=Coalesce('latest_daily_activity_at', 'last_login', 'created_at'))
			.filter(latest_activity_at__lte=cutoff)
			.order_by('latest_activity_at', 'id')
		)

		checked_count = 0
		nudged_count = 0
		skipped_count = 0
		failed_count = 0

		for user in users.iterator():
			checked_count += 1
			latest_activity_at = getattr(user, 'latest_activity_at', None)
			if not latest_activity_at:
				skipped_count += 1
				continue

			already_sent = InactivityNudgeLog.objects.filter(
				user=user,
				threshold_days=threshold_days,
				latest_activity_at=latest_activity_at,
			).exists()
			if already_sent:
				skipped_count += 1
				continue

			days_inactive = max((timezone.now() - latest_activity_at).days, threshold_days)
			subject, text, html = build_inactivity_nudge_email(
				name=getattr(user, 'name', '') or getattr(user, 'email', '') or 'there',
				days_inactive=days_inactive,
			)

			try:
				send_mailgun_email(
					to_email=user.email,
					subject=subject,
					text=text,
					html=html,
					tags=['inactivity_nudge', f'{threshold_days}_days'],
				)
			except EmailSendError:
				failed_count += 1
				continue

			InactivityNudgeLog.objects.create(
				user=user,
				latest_activity_at=latest_activity_at,
				threshold_days=threshold_days,
			)
			nudged_count += 1

		return Response(
			{
				'threshold_days': threshold_days,
				'cutoff_at': cutoff.isoformat(),
				'checked_count': checked_count,
				'nudged_count': nudged_count,
				'skipped_count': skipped_count,
				'failed_count': failed_count,
			},
			status=status.HTTP_200_OK,
		)
