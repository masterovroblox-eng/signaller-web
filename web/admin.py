from django.contrib import admin
from .models import Staff, Investigation, AuditLog, DiscordWebhook

@admin.register(Staff)
class StaffAdmin(admin.ModelAdmin):
    list_display = ('username', 'role', 'is_locked', 'must_change_password', 'created_at')
    search_fields = ('username', 'role')

@admin.register(Investigation)
class InvestigationAdmin(admin.ModelAdmin):
    list_display = ('id', 'title', 'reference_code', 'status', 'opened_by', 'created_at')
    search_fields = ('title', 'reference_code', 'location')

admin.site.register(AuditLog)
admin.site.register(DiscordWebhook)