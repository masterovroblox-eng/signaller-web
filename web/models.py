import uuid
import random
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils import timezone


class StaffManager(BaseUserManager):
    def create_user(self, username, password=None, **extra_fields):
        if not username:
            raise ValueError('Username is required')
        user = self.model(username=username, **extra_fields)
        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()
        user.save(using=self._db)
        return user

    def create_superuser(self, username, password=None, **extra_fields):
        extra_fields.setdefault('role', 'admin')
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('must_change_password', True)
        return self.create_user(username, password, **extra_fields)


ROLE_CHOICES = [
    ('staff', 'Staff (Supervisor)'),
    ('controller', 'Controller'),
    ('admin', 'Admin'),
]


class Staff(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=150, primary_key=True)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='staff')
    must_change_password = models.BooleanField(default=True)
    on_loa = models.BooleanField(default=False)
    is_locked = models.BooleanField(default=False)
    locked_by = models.CharField(max_length=150, blank=True, null=True)
    locked_at = models.DateTimeField(blank=True, null=True)
    roblox_username = models.CharField(max_length=150, blank=True, null=True)
    discord_username = models.CharField(max_length=150, blank=True, null=True)
    discord_id = models.CharField(max_length=150, blank=True, null=True)
    discord_avatar = models.CharField(max_length=255, blank=True, null=True)
    discord_connected_at = models.DateTimeField(blank=True, null=True)
    contact_info = models.TextField(blank=True, null=True)
    admin_notes = models.TextField(blank=True, null=True)
    joined_at = models.DateField(blank=True, null=True)
    created_at = models.DateTimeField(default=timezone.now)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = StaffManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = []

    class Meta:
        verbose_name = 'Staff'
        verbose_name_plural = 'Staff'

    def __str__(self):
        return self.username

    @property
    def is_admin(self):
        return self.role == 'admin'

    @property
    def is_owner(self):
        # first admin created
        first = Staff.objects.filter(role='admin').order_by('created_at').first()
        return first is not None and first.username == self.username


class Investigation(models.Model):
    STATUS_CHOICES = [('open', 'Open'), ('closed', 'Closed')]
    title = models.CharField(max_length=255)
    reference_code = models.CharField(max_length=20, unique=True, blank=True, null=True)
    incident_date = models.DateField(blank=True, null=True)
    location = models.CharField(max_length=255, blank=True, null=True)
    involved_parties = models.TextField(blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    outcome = models.TextField(blank=True, null=True)
    findings = models.TextField(blank=True, null=True)
    recommendations = models.TextField(blank=True, null=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='open')
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(blank=True, null=True)
    closed_at = models.DateTimeField(blank=True, null=True)
    closed_by = models.CharField(max_length=150, blank=True, null=True)
    opened_by = models.CharField(max_length=150, blank=True, null=True)
    share_token = models.UUIDField(default=uuid.uuid4, unique=True)
    mitigating_circumstances = models.TextField(blank=True, null=True)
    aggravating_circumstances = models.TextField(blank=True, null=True)
    witness_statements = models.JSONField(default=list, blank=True)
    approving_signature = models.TextField(blank=True, null=True)
    offender_rank = models.CharField(max_length=150, blank=True, null=True)
    previous_history = models.TextField(blank=True, null=True)
    investigators = models.TextField(blank=True, null=True)
    is_redacted = models.BooleanField(default=False)

    class Meta:
        ordering = ['-created_at']

    def save(self, *args, **kwargs):
        if not self.reference_code:
            while True:
                code = 'SYR-' + str(random.randint(0, 999999)).zfill(6)
                if not Investigation.objects.filter(reference_code=code).exists():
                    self.reference_code = code
                    break
        super().save(*args, **kwargs)

    def __str__(self):
        return self.title


class AuditLog(models.Model):
    created_at = models.DateTimeField(default=timezone.now)
    performed_by = models.CharField(max_length=150)
    action = models.CharField(max_length=100)
    target = models.CharField(max_length=255, blank=True, null=True)
    detail = models.TextField(blank=True, null=True)

    class Meta:
        ordering = ['-created_at']


class DiscordWebhook(models.Model):
    name = models.CharField(max_length=100, default='default')
    url = models.URLField()
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(default=timezone.now)