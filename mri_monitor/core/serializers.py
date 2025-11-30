from rest_framework import serializers
from .models import Device, Sensor, SensorReading, ErrorReport, ServiceLog

class DeviceSerializer(serializers.ModelSerializer):
    status = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = Device
        fields = ['id', 'member_id', 'name', 'created_at', 'status']

    def get_status(self, obj):
        # el cálculo real se delega en una función que inyectaremos desde api.views
        # cuando DeviceSerializer se use desde la vista /api/devices, la vista
        # añadirá al contexto la función 'compute_device_status' para evitar dependencias circulares.
        compute_fn = self.context.get('compute_device_status')
        if callable(compute_fn):
            try:
                return compute_fn(obj)
            except Exception:
                return "unknown"
        return "unknown"


class SensorSerializer(serializers.ModelSerializer):
    # device -> mostrar datos del device (read-only)
    device = DeviceSerializer(read_only=True)

    class Meta:
        model = Sensor
        fields = ['id', 'device', 'name', 'code', 'type', 'last_value', 'status', 'timestamp']

class SensorReadingSerializer(serializers.ModelSerializer):
    # mostrar sensor y device embebidos (read-only)
    sensor = SensorSerializer(read_only=True)
    device = DeviceSerializer(read_only=True)

    class Meta:
        model = SensorReading
        fields = ['id', 'device', 'sensor', 'value_text', 'value_numeric', 'received_at', 'generated_at', 'source_member']

class ErrorReportSerializer(serializers.ModelSerializer):
    device = DeviceSerializer(read_only=True)
    sensor = SensorSerializer(read_only=True)

    class Meta:
        model = ErrorReport
        fields = ['id', 'device', 'sensor', 'error_code', 'abstract', 'detail', 'generated_at', 'raw_xml', 'is_resolved', 'reported_at']

class ServiceLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = ServiceLog
        fields = [
            'id', 'device', 'service_type', 'notes',
            'coldhead_hours', 'compressor_hours', 'adsorber_hours',
            'created_at',
        ]
