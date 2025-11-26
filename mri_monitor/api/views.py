import logging
import os
import json
import re
from typing import Optional, Dict

from django.conf import settings
from django.db.models import Q
from django.contrib.auth import authenticate, login as django_login, logout as django_logout
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.models import User
from django.core.mail import EmailMessage

from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.http import JsonResponse

from django.views.decorators.csrf import csrf_exempt

from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status

from mri_monitor.core.models import Device, Sensor, SensorReading, ErrorReport
from mri_monitor.core.serializers import (
    SensorSerializer,
    SensorReadingSerializer,
    ErrorReportSerializer,
    DeviceSerializer
)

logger = logging.getLogger(__name__)

# =====================================================================
# =====================   PARSE THRESHOLDS   ==========================
# =====================================================================

BASE_CONFIG_PATH = os.path.join(settings.BASE_DIR, "mri_monitor", "config")
VALORES_FILE = os.path.join(BASE_CONFIG_PATH, "valores_sensores_referencia.json")

def load_reference_values():
    try:
        with open(VALORES_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        logger.exception("No se pudo leer valores_sensores_referencia.json")
        return {}

NUM_RE = r"(-?\d+(?:\.\d+)?)"
RANGE_RE = re.compile(rf"{NUM_RE}\s*-\s*{NUM_RE}")
COMP_RE = re.compile(rf"([<>])\s*{NUM_RE}")

def _parse_threshold_segment(text: str) -> Dict[str, list]:
    out = {}
    for key in ("warning", "critical", "normal", "optimal"):
        m = re.search(rf"{key}\s*:\s*([^,;]+)", text, flags=re.IGNORECASE)
        if m:
            seg = m.group(1).strip()
            mr = RANGE_RE.search(seg)
            if mr:
                low = float(mr.group(1))
                high = float(mr.group(2))
                out[key] = [("range", low, high)]
                continue

            mc = COMP_RE.search(seg)
            if mc:
                comp = mc.group(1)
                val = float(mc.group(2))
                out[key] = [("gt", val)] if comp == ">" else [("lt", val)]
                continue

            mnum = re.search(NUM_RE, seg)
            if mnum:
                out[key] = [("eq", float(mnum.group(1)))]

    return out

def parse_reference_map(ref_map: dict) -> dict:
    parsed = {}
    for k, v in ref_map.items():
        if isinstance(v, str):
            parsed[k.upper()] = _parse_threshold_segment(v)
        elif isinstance(v, dict):
            parsed[k.upper()] = v
        else:
            parsed[k.upper()] = {}
    return parsed

REF_PARSED = parse_reference_map(load_reference_values())

def _evaluate_value_against_thresholds(val: float, parsed_rules: dict) -> Optional[str]:
    if not parsed_rules:
        return None

    crit = parsed_rules.get("critical") or parsed_rules.get("crit")
    warn = parsed_rules.get("warning") or parsed_rules.get("warn")

    def matches(rule_list, value):
        if not rule_list:
            return False
        for r in rule_list:
            kind = r[0]
            if kind == "range":
                _, low, high = r
                if low <= value <= high:
                    return True
            elif kind == "gt":
                _, th = r
                if value > th:
                    return True
            elif kind == "lt":
                _, th = r
                if value < th:
                    return True
            elif kind == "eq":
                _, th = r
                if value == th:
                    return True
        return False

    if crit and matches(crit, val):
        return "critical"
    if warn and matches(warn, val):
        return "warning"
    return "normal"

def find_rule_for_sensor(sensor: Sensor) -> dict:
    candidates = []
    if sensor.code:
        candidates.append(sensor.code.upper())
    if sensor.name:
        candidates.append(sensor.name.upper())
        if sensor.code:
            candidates.append(f"{sensor.code.upper()}_{sensor.name.upper()}")
            candidates.append(f"{sensor.name.upper()}_{sensor.code.upper()}")

    candidates = [c for c in dict.fromkeys(candidates) if c]

    for c in candidates:
        if c in REF_PARSED:
            return REF_PARSED[c]
        for k in REF_PARSED.keys():
            if c in k or k in c:
                return REF_PARSED[k]

    return {}

def compute_device_status(device: Device) -> str:
    warnings = 0
    criticals = 0

    sensors = Sensor.objects.filter(device=device)

    for s in sensors:
        val = getattr(s, "last_value", None)
        if val is None:
            continue

        try:
            val = float(val)
        except Exception:
            continue

        name_upper = (s.name or "").upper()
        code_upper = (s.code or "").upper()

        # Helio → quench <20%
        if ("HE" in name_upper and "LEVEL" in name_upper) or "HELIUM" in name_upper or "A2" in code_upper:
            if val < 20:
                return "quench"

        rule = find_rule_for_sensor(s)
        if not rule:
            continue

        state = _evaluate_value_against_thresholds(val, rule)
        if state == "critical":
            criticals += 1
        elif state == "warning":
            warnings += 1

    if criticals > 1:
        return "critical"
    if criticals == 1:
        return "urgent"
    if warnings > 2:
        return "high"
    if 1 <= warnings <= 2:
        return "low"

    return "ok"


# =====================================================================
# =========================   API ENDPOINTS   ==========================
# =====================================================================

@api_view(['GET'])
def sensors_list(request):
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
    qs = SensorReading.objects.select_related('sensor','device').order_by('-generated_at', '-received_at')
    if member:
        qs = qs.filter(device__member_id=member)

    serializer = SensorReadingSerializer(qs, many=True)
    return Response(serializer.data)


@api_view(['GET'])
def sensor_readings(request):
    try:
        member = request.GET.get('member_id')
        sensor_q = request.GET.get('sensor_name') or request.GET.get('sensor_code')
        limit = request.GET.get('limit')

        qs = SensorReading.objects.select_related('sensor', 'device').order_by('-generated_at', '-received_at')

        if member:
            qs = qs.filter(device__member_id=member)

        if sensor_q:
            qs = qs.filter(
                Q(sensor__code__iexact=sensor_q) |
                Q(sensor__name__icontains=sensor_q)
            )

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
        logger.exception("Error in sensor_readings endpoint")
        return Response({'detail': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
def notifications_list(request):
    member = request.GET.get('member_id')
    code = request.GET.get('error_code')

    qs = ErrorReport.objects.all().order_by('-reported_at')
    if member:
        qs = qs.filter(device__member_id=member)
    if code:
        qs = qs.filter(error_code=code)

    serializer = ErrorReportSerializer(qs[:200], many=True)
    return Response(serializer.data)


# =====================  DEVICES LIST (MODIFICADO) =========================

@api_view(['GET'])
def devices_list(request):
    qs = Device.objects.all().order_by('member_id')
    serializer = DeviceSerializer(
        qs,
        many=True,
        context={"compute_device_status": compute_device_status}
    )
    return Response(serializer.data)


# =====================================================================
# ====================     LOGIN / LOGOUT / RESET    ==================
# =====================================================================

@csrf_exempt
def login_view(request):
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
        django_login(request, user)
        return JsonResponse({'success': True, 'user': {'username': user.username, 'id': user.id}})
    else:
        return JsonResponse({'success': False, 'detail': 'Invalid credentials'}, status=401)


@csrf_exempt
def logout_view(request):
    if request.method != 'POST':
        return JsonResponse({'success': False, 'detail': 'Only POST allowed'}, status=405)
    django_logout(request)
    return JsonResponse({'success': True})


@csrf_exempt
def password_reset_request(request):
    if request.method != 'POST':
        return JsonResponse({'success': False, 'detail': 'Only POST'}, status=405)

    try:
        payload = json.loads(request.body.decode('utf-8'))
    except Exception:
        return JsonResponse({'success': False, 'detail': 'Invalid JSON'}, status=400)

    email = payload.get('email', '').strip()
    if not email:
        return JsonResponse({'success': False, 'detail': 'Missing email'}, status=400)

    qs = User.objects.filter(email__iexact=email, is_active=True)
    if not qs.exists():
        return JsonResponse({'success': True})

    for user in qs:
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        frontend_base = getattr(settings, 'FRONTEND_BASE', 'http://localhost:5173')
        reset_path = f"/reset-password?uid={uid}&token={token}"
        reset_url = frontend_base.rstrip('/') + reset_path

        subject = "Password reset for your account"
        message = f"Hi {user.username},\n\n"
        message += "You (or someone else) requested a password reset. Click the link below to reset your password:\n\n"
        message += reset_url + "\n\n"
        message += "If you didn't request this, ignore this message.\n"

        from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'comercial4d@4dmedical.ai')
        to = [user.email]

        email = EmailMessage(subject=subject, body=message, from_email=from_email, to=to)
        # text/plain by default. If quieres HTML, usa email.content_subtype = "html" y un body con HTML.
        try:
            email.send(fail_silently=False)
            logger.info("Password reset email sent to %s", user.email)
        except Exception as e:
            # No fallamos la petición, pero logueamos el error para depuración
            logger.exception("Failed to send password reset email to %s: %s", user.email, e)

    return JsonResponse({'success': True})

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

    user.set_password(new_password)
    user.save()
    return JsonResponse({'success': True})
