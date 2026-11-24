from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('login', views.login_view, name='login'),
    path('logout', views.logout_view, name='logout'),
    path('investigations', views.investigations_view, name='investigations'),
    path('investigation/<int:pk>', views.investigation_view, name='investigation'),
    path('admin', views.admin_view, name='admin'),
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