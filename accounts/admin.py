import csv
from datetime import timedelta

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.db.models import Count
from django.db.models.functions import TruncDate, TruncMonth, TruncWeek
from django.http import HttpResponse
from django.template.response import TemplateResponse
from django.urls import path, reverse
from django.utils import timezone

from .models import AccountDeletionRequest, PasswordResetOTP, User


def _build_grouped_rows(queryset, field_name, truncator):
	rows = (
		queryset.annotate(period=truncator(field_name))
		.values('period')
		.annotate(total=Count('id'))
		.order_by('period')
	)
	return [
		{
			'period': row['period'],
			'total': row['total'],
		}
		for row in rows
		if row['period'] is not None
	]


def _rows_for_export(rows, metric, period_type):
	return [
		{
			'metric': metric,
			'period_type': period_type,
			'period_start': row['period'],
			'value': row['total'],
		}
		for row in rows
	]


@admin.register(User)
class UserAdmin(BaseUserAdmin):
	model = User
	list_display = ('id', 'email', 'phone', 'name', 'is_active', 'is_staff', 'created_at')
	list_filter = ('is_active', 'is_staff', 'is_superuser')
	search_fields = ('email', 'phone', 'name')
	ordering = ('email',)
	change_list_template = 'admin/accounts/user/change_list.html'

	fieldsets = (
		(None, {'fields': ('email', 'password')}),
		('Personal info', {'fields': ('name', 'phone', 'avatar')}),
		('Verification', {'fields': ('phone_verified', 'email_verified')}),
		('Preferences', {'fields': ('preferred_notification_email', 'preferred_notification_phone')}),
		('Permissions', {
			'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
		}),
		('Important dates', {'fields': ('last_login', 'created_at', 'updated_at')}),
	)

	add_fieldsets = (
		(None, {
			'classes': ('wide',),
			'fields': ('email', 'phone', 'name', 'password1', 'password2'),
		}),
	)

	readonly_fields = ('created_at', 'updated_at')

	def get_urls(self):
		urls = super().get_urls()
		custom_urls = [
			path(
				'stats-dashboard/',
				self.admin_site.admin_view(self.stats_dashboard_view),
				name='accounts_user_stats_dashboard',
			),
			path(
				'stats-dashboard/export/csv/',
				self.admin_site.admin_view(self.export_stats_csv),
				name='accounts_user_stats_export_csv',
			),
			path(
				'stats-dashboard/export/excel/',
				self.admin_site.admin_view(self.export_stats_excel),
				name='accounts_user_stats_export_excel',
			),
		]
		return custom_urls + urls

	def changelist_view(self, request, extra_context=None):
		extra_context = extra_context or {}
		extra_context['stats_dashboard_url'] = reverse('admin:accounts_user_stats_dashboard')
		return super().changelist_view(request, extra_context=extra_context)

	def _collect_stats(self):
		now = timezone.now()
		today = now.date()

		active_users_base_qs = User.objects.filter(is_active=True, last_login__isnull=False)
		signups_base_qs = User.objects.all()

		daily_active_rows = _build_grouped_rows(
			active_users_base_qs.filter(last_login__date__gte=today - timedelta(days=29)),
			'last_login',
			TruncDate,
		)
		weekly_active_rows = _build_grouped_rows(
			active_users_base_qs.filter(last_login__date__gte=today - timedelta(weeks=11)),
			'last_login',
			TruncWeek,
		)

		daily_signup_rows = _build_grouped_rows(
			signups_base_qs.filter(created_at__date__gte=today - timedelta(days=29)),
			'created_at',
			TruncDate,
		)
		weekly_signup_rows = _build_grouped_rows(
			signups_base_qs.filter(created_at__date__gte=today - timedelta(weeks=11)),
			'created_at',
			TruncWeek,
		)
		monthly_signup_rows = _build_grouped_rows(
			signups_base_qs,
			'created_at',
			TruncMonth,
		)

		this_week_start = today - timedelta(days=today.weekday())
		this_month_start = today.replace(day=1)

		kpis = {
			'active_today': active_users_base_qs.filter(last_login__date=today).count(),
			'active_this_week': active_users_base_qs.filter(last_login__date__gte=this_week_start).count(),
			'signups_today': signups_base_qs.filter(created_at__date=today).count(),
			'signups_this_week': signups_base_qs.filter(created_at__date__gte=this_week_start).count(),
			'signups_this_month': signups_base_qs.filter(created_at__date__gte=this_month_start).count(),
			'signups_all_time': signups_base_qs.count(),
		}

		export_rows = []
		export_rows.extend(_rows_for_export(daily_active_rows, 'active_users', 'day'))
		export_rows.extend(_rows_for_export(weekly_active_rows, 'active_users', 'week'))
		export_rows.extend(_rows_for_export(daily_signup_rows, 'signups', 'day'))
		export_rows.extend(_rows_for_export(weekly_signup_rows, 'signups', 'week'))
		export_rows.extend(_rows_for_export(monthly_signup_rows, 'signups', 'month'))
		export_rows.append(
			{
				'metric': 'signups',
				'period_type': 'all_time',
				'period_start': None,
				'value': kpis['signups_all_time'],
			}
		)

		return {
			'daily_active_rows': daily_active_rows,
			'weekly_active_rows': weekly_active_rows,
			'daily_signup_rows': daily_signup_rows,
			'weekly_signup_rows': weekly_signup_rows,
			'monthly_signup_rows': monthly_signup_rows,
			'kpis': kpis,
			'export_rows': export_rows,
		}

	def stats_dashboard_view(self, request):
		stats = self._collect_stats()

		context = {
			**self.admin_site.each_context(request),
			'title': 'User Stats Dashboard',
			'opts': self.model._meta,
			'has_view_permission': self.has_view_permission(request),
			'stats_dashboard_url': reverse('admin:accounts_user_stats_dashboard'),
			'export_csv_url': reverse('admin:accounts_user_stats_export_csv'),
			'export_excel_url': reverse('admin:accounts_user_stats_export_excel'),
			'kpis': stats['kpis'],
			'active_daily_labels': [row['period'].strftime('%Y-%m-%d') for row in stats['daily_active_rows']],
			'active_daily_values': [row['total'] for row in stats['daily_active_rows']],
			'active_weekly_labels': [row['period'].strftime('%Y-%m-%d') for row in stats['weekly_active_rows']],
			'active_weekly_values': [row['total'] for row in stats['weekly_active_rows']],
			'signups_daily_labels': [row['period'].strftime('%Y-%m-%d') for row in stats['daily_signup_rows']],
			'signups_daily_values': [row['total'] for row in stats['daily_signup_rows']],
			'signups_weekly_labels': [row['period'].strftime('%Y-%m-%d') for row in stats['weekly_signup_rows']],
			'signups_weekly_values': [row['total'] for row in stats['weekly_signup_rows']],
			'signups_monthly_labels': [row['period'].strftime('%Y-%m') for row in stats['monthly_signup_rows']],
			'signups_monthly_values': [row['total'] for row in stats['monthly_signup_rows']],
		}

		return TemplateResponse(request, 'admin/accounts/user/stats_dashboard.html', context)

	def export_stats_csv(self, request):
		stats = self._collect_stats()
		response = HttpResponse(content_type='text/csv')
		response['Content-Disposition'] = 'attachment; filename="user_stats_dashboard.csv"'

		writer = csv.writer(response)
		writer.writerow(['metric', 'period_type', 'period_start', 'value'])
		for row in stats['export_rows']:
			writer.writerow([
				row['metric'],
				row['period_type'],
				row['period_start'].isoformat() if row['period_start'] else '',
				row['value'],
			])

		return response

	def export_stats_excel(self, request):
		stats = self._collect_stats()
		response = HttpResponse(content_type='application/vnd.ms-excel')
		response['Content-Disposition'] = 'attachment; filename="user_stats_dashboard.xls"'

		writer = csv.writer(response, delimiter='\t')
		writer.writerow(['metric', 'period_type', 'period_start', 'value'])
		for row in stats['export_rows']:
			writer.writerow([
				row['metric'],
				row['period_type'],
				row['period_start'].isoformat() if row['period_start'] else '',
				row['value'],
			])

		return response


@admin.register(AccountDeletionRequest)
class AccountDeletionRequestAdmin(admin.ModelAdmin):
	list_display = ('id', 'user', 'created_at')
	search_fields = ('user__email', 'user__phone', 'reason')
	ordering = ('-created_at',)


@admin.register(PasswordResetOTP)
class PasswordResetOTPAdmin(admin.ModelAdmin):
	list_display = ('id', 'user', 'otp_expires_at', 'otp_used_at', 'reset_token_expires_at', 'reset_token_used_at', 'created_at')
	search_fields = ('user__email', 'user__phone')
	ordering = ('-created_at',)

