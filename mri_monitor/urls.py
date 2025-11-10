from django.contrib import admin
from django.urls import path
from mri_monitor.soap_server import views as soap_views
from mri_monitor.api import views as api_views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('a2b/ACM', soap_views.soap_endpoint),
    path('a2b/Registration', soap_views.soap_endpoint),
    path('a2b/RemoteAccessManager', soap_views.soap_endpoint),
    path('a2b/MonitorManager', soap_views.soap_endpoint),
    path('api/sensors', api_views.sensors_list),
    path('api/sensor_readings', api_views.sensor_readings),
    path('api/notifications', api_views.notifications_list),
    path('api/devices', api_views.devices_list),

]
