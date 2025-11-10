from django.contrib import admin
from .models import Device, Sensor, SensorReading, ErrorReport, SensorDefinition

admin.site.register(Device)
admin.site.register(Sensor)
admin.site.register(SensorReading)
admin.site.register(ErrorReport)
admin.site.register(SensorDefinition)
