from django.urls import path
from . import views

urlpatterns = [
    # Homepage – requires login, shows a role‑based start page
    path('', views.home_view, name='home'),

    # Supervisor page – SV can see signallers and their write‑ups, add a signaller (1 per hour)
    path('supervisor/', views.supervisor_view, name='supervisor'),

    # Administrator page – audit log, member list, add signaller/supervisor (admin only)
    path('admin-dashboard/', views.admin_dashboard_view, name='admin_dashboard'),

    # Write‑up creation (supervisor) and approval (manager)
    path('writeup/create/', views.writeup_create, name='writeup_create'),
    path('writeup/approve/<int:pk>/', views.writeup_approve, name='writeup_approve'),
    path('writeup/pdf/<int:pk>/', views.writeup_pdf, name='writeup_pdf'),

    # Investigation edit (with proper CSS)
    path('investigation/<int:pk>/edit/', views.investigation_edit, name='investigation_edit'),

    path('reset-admin', views.reset_admin_view, name='reset_admin'),
    path('login', views.login_view, name='login'),
    path('logout', views.logout_view, name='logout'),
    path('investigations', views.investigations_view, name='investigations'),
    path('investigation/<int:pk>', views.investigation_view, name='investigation'),
    path('admin', views.admin_view, name='admin'),  # legacy, kept for backwards compat
    path('privacy', views.privacy_view, name='privacy'),
    path('terms', views.terms_view, name='terms'),
    path('404', views.not_found_view, name='not_found'),

    # API
    path('api/me', views.api_me),
    path('api/login', views.api_login),
    path('api/set-password', views.api_set_password),
    path('api/logout', views.api_logout),
    path('api/investigations', views.api_investigations),
    path('api/investigations/<int:pk>', views.api_investigation),
    path('api/investigations/<int:pk>/close', views.api_close_investigation),
    path('api/investigations/<int:pk>/reopen', views.api_reopen_investigation),
    path('api/admin/staff', views.api_admin_staff),
    path('api/admin/staff/<str:username>', views.api_admin_staff_detail),
    path('api/admin/staff/<str:username>/reset-password', views.api_admin_reset_password),
    path('api/admin/staff/<str:username>/lock', views.api_admin_lock),
    path('api/admin/staff/<str:username>/rename', views.api_admin_rename),
]