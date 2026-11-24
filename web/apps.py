import os
from django.apps import AppConfig


class WebConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'web'

    def ready(self):
        # Bootstrap an admin account at runtime if none exists (no shell needed).
        try:
            from web.models import Staff
            username = os.environ.get('DJANGO_SUPERUSER_USERNAME', 'admin')
            password = os.environ.get('DJANGO_SUPERUSER_PASSWORD', 'ChangeMe123!')
            if Staff.objects.filter(role='admin').exists():
                return
            user = Staff(username=username, role='admin', must_change_password=True, is_staff=True, is_superuser=True)
            user.set_password(password)
            user.save()
            print(f'[ensure_admin] Created bootstrap admin "{username}".', flush=True)
        except Exception as e:
            print(f'[ensure_admin] skipped: {e}', flush=True)
