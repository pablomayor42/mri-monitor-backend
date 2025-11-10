from rest_framework import serializers
from .models import Device, Sensor, SensorReading, ErrorReport

class DeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = ['id', 'member_id', 'name', 'created_at']

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
