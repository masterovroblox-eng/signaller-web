from django.contrib import admin
from django.urls import path, include
from django.views.generic import RedirectView

urlpatterns = [
    path('django-admin/', admin.site.urls),
    path('', include('web.urls')),
]