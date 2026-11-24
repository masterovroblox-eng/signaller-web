import os
from django.core.management.base import BaseCommand
from web.models import Staff


class Command(BaseCommand):
    help = 'Ensure an admin account exists (bootstrap for Render).'

    def handle(self, *args, **options):
        username = os.environ.get('DJANGO_SUPERUSER_USERNAME', 'admin')
        password = os.environ.get('DJANGO_SUPERUSER_PASSWORD', 'ChangeMe123!')
        email = os.environ.get('DJANGO_SUPERUSER_EMAIL', 'admin@example.com')

        if Staff.objects.filter(username=username).exists():
            self.stdout.write(f'Admin "{username}" already exists.')
            return

        # If any admin exists, don't create another.
        if Staff.objects.filter(role='admin').exists():
            self.stdout.write('An admin already exists; skipping bootstrap.')
            return

        user = Staff(username=username, role='admin', must_change_password=True, is_staff=True, is_superuser=True)
        user.set_password(password)
        user.save()
        self.stdout.write(self.style.SUCCESS(f'Created bootstrap admin "{username}".'))