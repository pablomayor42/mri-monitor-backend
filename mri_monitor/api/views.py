from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from mri_monitor.core.models import Device, Sensor, SensorReading, ErrorReport
from mri_monitor.core.serializers import SensorSerializer, SensorReadingSerializer, ErrorReportSerializer, DeviceSerializer

@api_view(['GET'])
def sensors_list(request):
    """
    GET /api/sensors
    Optional query param: ?member_id=FI1126MR01SMM3
    """
    member = request.GET.get('member_id')
    if member:
        qs = Sensor.objects.filter(device__member_id=member).order_by('-timestamp')
    else:
        qs = Sensor.objects.all().order_by('-timestamp')
    serializer = SensorSerializer(qs, many=True)
    return Response(serializer.data)

@api_view(['GET'])
def sensor_readings(request):
    """
    GET /api/sensor_readings
    Optional params: member_id, sensor_name
    """
    member = request.GET.get('member_id')
    sensor_name = request.GET.get('sensor_name')
    qs = SensorReading.objects.all().order_by('-received_at')
    if member:
        qs = qs.filter(device__member_id=member)
    if sensor_name:
        qs = qs.filter(sensor__name=sensor_name)
    serializer = SensorReadingSerializer(qs[:200], many=True)  # limit 200 by default
    return Response(serializer.data)

@api_view(['GET'])
def notifications_list(request):
    """
    GET /api/notifications
    Returns ErrorReport entries (previously 'notifications' endpoint).
    Optional filters: ?member_id=... ?error_code=...
    """
    member = request.GET.get('member_id')
    code = request.GET.get('error_code')
    qs = ErrorReport.objects.all().order_by('-reported_at')
    if member:
        qs = qs.filter(device__member_id=member)
    if code:
        qs = qs.filter(error_code=code)
    serializer = ErrorReportSerializer(qs[:200], many=True)
    return Response(serializer.data)

@api_view(['GET'])
def devices_list(request):
    qs = Device.objects.all().order_by('member_id')
    serializer = DeviceSerializer(qs, many=True)
    return Response(serializer.data)
