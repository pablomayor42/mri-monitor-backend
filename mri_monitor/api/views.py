import logging
from django.db.models import Q

from django.contrib.auth import authenticate, login as django_login, logout as django_logout
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.models import User

from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str

from django.core.mail import send_mail

from django.template.loader import render_to_string

from django.conf import settings

from django.views.decorators.csrf import csrf_exempt

from django.middleware.csrf import get_token

from django.http import JsonResponse, HttpResponseBadRequest

import json

from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status

from mri_monitor.core.models import Device, Sensor, SensorReading, ErrorReport
from mri_monitor.core.serializers import SensorSerializer, SensorReadingSerializer, ErrorReportSerializer, DeviceSerializer

logger = logging.getLogger(__name__)

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
def sensor_readings_list(request):
    member = request.GET.get('member_id')
    qs = SensorReading.objects.select_related('sensor','device').order_by('-generated_at','-received_at')
    if member:
        qs = qs.filter(device__member_id=member)
    serializer = SensorReadingSerializer(qs, many=True)
    return Response(serializer.data)

@api_view(['GET'])
def sensor_readings(request):
    """
    Endpoint robusto para devolver lecturas de sensores.
    Query params:
      - member_id
      - sensor_name  (o sensor_code)
      - limit        (número máximo de filas, opcional)
    """
    try:
        member = request.GET.get('member_id')
        sensor_q = request.GET.get('sensor_name') or request.GET.get('sensor_code')
        limit = request.GET.get('limit')

        qs = SensorReading.objects.select_related('sensor', 'device').order_by('-generated_at', '-received_at')

        if member:
            qs = qs.filter(device__member_id=member)

        if sensor_q:
            # intenta por código exacto o por nombre conteniendo la cadena (case-insensitive)
            qs = qs.filter(Q(sensor__code__iexact=sensor_q) | Q(sensor__name__icontains=sensor_q))

        if limit:
            try:
                n = int(limit)
                if n > 0:
                    qs = qs[:n]
            except Exception:
                # si limit no es numérico, ignorarlo
                logger.warning("Invalid limit param: %r", limit)

        serializer = SensorReadingSerializer(qs, many=True)
        return Response(serializer.data)
    except Exception as e:
        # registrar la excepción completa en los logs del servidor
        logger.exception("Error in sensor_readings endpoint")
        # devolver JSON amigable al frontend (evita HTML 500 por defecto)
        return Response({'detail': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

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

@csrf_exempt
def login_view(request):
    """
    POST /api/login
    Body: { "username": "...", "password": "..." }
    Respuesta JSON:
      { "success": true, "user": { "username": "...", "id": ... } }
      o { "success": false, "detail": "..." }
    """
    if request.method != 'POST':
        return JsonResponse({'success': False, 'detail': 'Only POST allowed'}, status=405)

    try:
        payload = json.loads(request.body.decode('utf-8'))
    except Exception:
        return JsonResponse({'success': False, 'detail': 'Invalid JSON'}, status=400)

    username = payload.get('username') or payload.get('user') or ''
    password = payload.get('password') or ''

    if not username or not password:
        return JsonResponse({'success': False, 'detail': 'Missing credentials'}, status=400)

    user = authenticate(request, username=username, password=password)
    if user is not None:
        # crear sesión
        django_login(request, user)
        # opcional: devuelve token o info
        return JsonResponse({'success': True, 'user': {'username': user.username, 'id': user.id}})
    else:
        return JsonResponse({'success': False, 'detail': 'Invalid credentials'}, status=401)


@csrf_exempt
def logout_view(request):
    if request.method != 'POST':
        return JsonResponse({'success': False, 'detail': 'Only POST allowed'}, status=405)
    django_logout(request)
    return JsonResponse({'success': True})

# POST /api/password_reset
@csrf_exempt
def password_reset_request(request):
    if request.method != 'POST':
        return JsonResponse({'success': False, 'detail': 'Only POST'}, status=405)
    try:
        payload = json.loads(request.body.decode('utf-8'))
    except Exception:
        return JsonResponse({'success': False, 'detail': 'Invalid JSON'}, status=400)
    email = payload.get('email','').strip()
    if not email:
        return JsonResponse({'success': False, 'detail': 'Missing email'}, status=400)

    # find users with that email (could be multiple)
    qs = User.objects.filter(email__iexact=email, is_active=True)
    if not qs.exists():
        # Do not reveal existence: return success so attackers can't enumerate emails
        return JsonResponse({'success': True})

    for user in qs:
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        # Build reset link - adjust frontend domain/route as needed
        # We'll send a link to a frontend route like: https://yourfrontend/reset-password/?uid=...&token=...
        frontend_base = getattr(settings, 'FRONTEND_BASE', 'http://localhost:5173')
        reset_path = f"/reset-password?uid={uid}&token={token}"
        reset_url = frontend_base.rstrip('/') + reset_path

        # Render email (text/plain)
        subject = "Password reset for your account"
        message = f"Hi {user.username},\n\n"
        message += "You (or someone else) requested a password reset. Click the link below to reset your password:\n\n"
        message += reset_url + "\n\n"
        message += "If you didn't request this, ignore this message.\n"

        # send email
        try:
            send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email], fail_silently=False)
        except Exception:
            # log error, but don't crash
            pass

    return JsonResponse({'success': True})

# POST /api/password_reset_confirm
# body: { uid: '...', token: '...', new_password: '...' }
@csrf_exempt
def password_reset_confirm(request):
    if request.method != 'POST':
        return JsonResponse({'success': False, 'detail': 'Only POST'}, status=405)
    try:
        payload = json.loads(request.body.decode('utf-8'))
    except Exception:
        return JsonResponse({'success': False, 'detail': 'Invalid JSON'}, status=400)
    uidb64 = payload.get('uid')
    token = payload.get('token')
    new_password = payload.get('new_password')

    if not uidb64 or not token or not new_password:
        return JsonResponse({'success': False, 'detail': 'Missing fields'}, status=400)

    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except Exception:
        return JsonResponse({'success': False, 'detail': 'Invalid token or user'}, status=400)

    if not default_token_generator.check_token(user, token):
        return JsonResponse({'success': False, 'detail': 'Invalid or expired token'}, status=400)

    # set new password
    user.set_password(new_password)
    user.save()
    return JsonResponse({'success': True})