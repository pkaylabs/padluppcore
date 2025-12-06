from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from .models import User


@admin.register(User)
class UserAdmin(BaseUserAdmin):
	model = User
	list_display = ('id', 'email', 'phone', 'name', 'is_active', 'is_staff', 'created_at')
	list_filter = ('is_active', 'is_staff', 'is_superuser')
	search_fields = ('email', 'phone', 'name')
	ordering = ('email',)

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

