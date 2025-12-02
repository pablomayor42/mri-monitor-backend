# mri_monitor/core/models.py
import uuid
from django.db import models

class Device(models.Model):
    """
    Equipo MRI que envía datos vía SOAP.
    member_id coincide con el MemberId remoto.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    member_id = models.CharField(max_length=100, unique=True)   # e.g. "FI1126MR01SMM3"
    name = models.CharField(max_length=200, blank=True)         # opcional friendly name
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.member_id} ({self.name})" if self.name else self.member_id

class SensorDefinition(models.Model):
    """
    Definición opcional de sensores (A2 -> He_Level).
    """
    id = models.BigAutoField(primary_key=True)
    code = models.CharField(max_length=50, unique=True)
    key = models.CharField(max_length=100)
    unit = models.CharField(max_length=50, blank=True)
    description = models.TextField(blank=True)

    def __str__(self):
        return f"{self.code} -> {self.key}"

class Sensor(models.Model):
    """
    Sensor asociado a un Device.
    - name: clave lógica (p.ej. "He_Level")
    - code: código “crudo” del proveedor (p.ej. "A2")
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    device = models.ForeignKey(Device, on_delete=models.CASCADE, related_name='sensors', null=True, blank=True)
    name = models.CharField(max_length=200)   # key, e.g. "He_Level"
    code = models.CharField(max_length=50, blank=True)  # raw code: "A2"
    type = models.CharField(max_length=50, default='measured')
    last_value = models.CharField(max_length=200, blank=True)
    status = models.CharField(max_length=20, default='OK')
    timestamp = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('device', 'name')

    def __str__(self):
        return f"{self.device.member_id}:{self.name} ({self.code})"

class SensorReading(models.Model):
    """
    Histórico de lecturas. Asociado a Sensor y a Device para consultas rápidas.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    device = models.ForeignKey(Device, on_delete=models.CASCADE, related_name='readings', null=True, blank=True)
    sensor = models.ForeignKey(Sensor, on_delete=models.CASCADE, related_name='readings')
    value_text = models.CharField(max_length=200, blank=True)
    value_numeric = models.FloatField(null=True, blank=True)
    received_at = models.DateTimeField(auto_now_add=True)
    source_member = models.CharField(max_length=100, blank=True)
    generated_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=['device', 'sensor', 'received_at']),
        ]

    def __str__(self):
        return f"{self.device.member_id}:{self.sensor.name}@{self.received_at} = {self.value_text}"

class ErrorReport(models.Model):
    """
    Alarma/avería recibida vía SOAP (submitFault/EC codes).
    Guarda código, detalle, XML original y fechas.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    device = models.ForeignKey(Device, null=True, blank=True, on_delete=models.SET_NULL, related_name='errors')
    sensor = models.ForeignKey(Sensor, null=True, blank=True, on_delete=models.SET_NULL)
    error_code = models.CharField(max_length=100)   # normalizado, e.g. "25"
    abstract = models.CharField(max_length=200, blank=True)
    detail = models.TextField(blank=True)
    generated_at = models.DateTimeField(null=True, blank=True)
    raw_xml = models.TextField(blank=True)
    is_resolved = models.BooleanField(default=False)
    reported_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=['device', 'error_code', 'reported_at']),
        ]

    def __str__(self):
        return f"{self.device.member_id if self.device else 'UnknownDevice'} - {self.error_code} @ {self.reported_at}"

class ServiceLog(models.Model):
    """
    Entrada de historial de servicio de un dispositivo.
    Guarda tipo de servicio, notas y horas del equipo en el momento del servicio.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    device = models.ForeignKey(
        Device,
        on_delete=models.CASCADE,
        related_name='service_logs'
    )

    service_type = models.CharField(max_length=200, blank=True)
    notes = models.TextField()

    # Horas opcionales en el momento del servicio
    coldhead_hours = models.PositiveIntegerField(default=0)
    compressor_hours = models.PositiveIntegerField(default=0)
    adsorber_hours = models.PositiveIntegerField(default=0)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.device.member_id} | {self.service_type} | {self.created_at:%Y-%m-%d %H:%M}"
