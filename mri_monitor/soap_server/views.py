# mri_monitor/soap_server/views.py
import logging
import json
import os

from django.conf import settings
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from django.core.mail import EmailMessage
from django.contrib.auth.models import User

from datetime import datetime
from xml.etree import ElementTree as ET
from typing import Dict, Optional

from mri_monitor.core.models import Device, Sensor, SensorReading, ErrorReport

logger = logging.getLogger('mri_monitor.soap_server')

# --- CONFIG: carga de JSONs desde mri_monitor/config/ ---B
BASE_CONFIG_PATH = os.path.join(settings.BASE_DIR, "mri_monitor", "config")

def load_json(filename, default=None):
    if default is None:
        default = {}
    path = os.path.join(BASE_CONFIG_PATH, filename)
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

SENSORS_DEF = load_json("sensors.json", {})
COMPRESSOR_CODES = load_json("compressor_status_codes.json", {})
THRESHOLDS = load_json("valores_sensores_referencia.json", {})

# Construimos SENSOR_CODE_MAP tolerando dos formatos:
#  - "A2": { "key": "He_Level", "unit": "%", "description": "..." }
#  - "MM3R": "Magnon software version"  (string -> tratamos como descripción)
SENSOR_CODE_MAP = {}
for code, info in SENSORS_DEF.items():
    code_u = str(code).upper()
    if isinstance(info, dict):
        SENSOR_CODE_MAP[code_u] = (
            info.get("key", code_u),
            info.get("unit", ""),
            info.get("description", "")
        )
    else:
        # fallback: info es string (descripción)
        SENSOR_CODE_MAP[code_u] = (
            code_u,          # key: usar el código como key por defecto
            "",              # unidad unknown
            str(info)        # descripción proveniente del JSON
        )


ERROR_CODE_MAP = {
    "0": "No Error.",
    "1": "He Level too high.",
    "2": "He Level too low.",
    "3": "He Level Top too high.",
    "4": "He Level Top too low.",
    "5": "Water flow for compressor 1 too low.",
    "6": "Water flow for compressor 1 too high.",
    "7": "Water temp for compressor 1 too cold.",
    "8": "Water temp for compressor 1 too hot.",
    "9": "Water flow for compressor 2 too low.",
    "10": "Water flow for compressor 2 too high.",
    "11": "Water temp for compressor 2 too cold.",
    "12": "Water temp for compressor 2 too hot.",
    "13": "Shield temp too cold.",
    "14": "Shield temp too hot.",
    "15": "Recondensor RuO temp too low.",
    "16": "Recondensor RuO temp too high.",
    "17": "Recondensor Si410 temp too low.",
    "18": "Recondensor Si410 temp too high.",
    "19": "Recondensor Si410 (2A) temp too low.",
    "20": "Recondensor Si410 (2A) temp too high.",
    "21": "Recondensor Si410 (2B) temp too low.",
    "22": "Recondensor Si410 (2B) temp too high.",
    "23": "Coldhead RuO temp too hot.",
    "24": "Coldhead RuO temp too cold.",
    "25": "Vessel pressure too high.",
    "26": "Vessel pressure too low.",
    "27": "EC_SPARE_SR1A_HIGH.",
    "28": "EC_SPARE_SR1A_LOW.",
    "29": "EC_SPARE_SR1B_HIGH.",
    "30": "EC_SPARE_SR1B_LOW.",
    "31": "EC_SPARE_CMP1A_HIGH.",
    "32": "EC_SPARE_CMP1A_LOW.",
    "33": "EC_SPARE_CMP1B_HIGH.",
    "34": "EC_SPARE_CMP1B_LOW.",
    "35": "EC_SPARE_CMP1C_HIGH.",
    "36": "EC_SPARE_CMP1C_LOW.",
    "37": "SingleStage temp too low HFO Bottom shield problem.",
    "38": "SingleStage temp too high HFO Bottom shield problem.",
    "44": "Vessel pressure sensor cable disconnected.",
    "45": "HeLevel cable disconnected.",
    "46": "HeLevelTop cable disconnected.",
    "47": "Recondensor RuO cable disconnected.",
    "48": "Coldhead RuO sensor cable disconnected.",
    "49": "Shield temp sensor cable disconnected.",
    "50": "Recondensor Si410 cable disconnected.",
    "51": "Recondensor Si410 (2A) cable disconnected.",
    "52": "Recondensor Si410 (2A) cable disconnected.",
    "53": "The RuO buffer is drawing too much current from Magmon.",
    "54": "The remote alarm is drawing too much current from Magmon.",
    "55": "The 12v heater is drawing too much current from Magmon.",
    "56": "Water meter 1 is drawing too much current from Magmon.",
    "57": "Water meter 2 is drawing too much current from Magmon.",
    "58": "The 12v heater is under voltage when turned on.",
    "65": "Magmon driving too much current into the HeLevel sensor.",
    "66": "Magmon not driving enough current into the HeLevel sensor.",
    "67": "Magmon driving too much current into the HeLevelTop sensor.",
    "68": "Magmon not driving enough current into the HeLevelTop sensor.",
    "69": "Magmon driving too much current into the Recondensor RuO sensor.",
    "70": "Magmon not driving enough current into the Recondensor RuO sensor.",
    "71": "Magmon driving too much current into the coldhead RuO sensor.",
    "72": "Magmon not driving enough current into the coldhead RuO sensor.",
    "73": "Magmon driving too much current into the Recondensor Si410 sensor.",
    "74": "Magmon not driving enough current into the Recondensor Si410 sensor.",
    "75": "Magmon driving too much current into the Recondensor Si410 (2A) sensor.",
    "76": "Magmon not driving enough current into the Recondensor Si410 (2A) sensor.",
    "77": "Magmon driving too much current into the Recondensor Si410 (2B) sensor.",
    "78": "Magmon not driving enough current into the Recondensor Si410 (2B) sensor.",
    "79": "Magmon driving too much current into the Shield Si410 sensor.",
    "80": "Magmon not driving enough current into the Shield Si410 sensor.",
    "81": "Magmon supplied 12v for the RuO buffer is too high.",
    "82": "Magmon supplied 12v for the RuO buffer is too low.",
    "83": "Magmon internal 12v supply is too high.",
    "84": "Magmon internal 12v supply is too low.",
    "85": "Magmon internal -12v supply is too high.",
    "86": "Magmon internal -12v supply is too low.",
    "87": "Magmon supplied -12v for the RuO buffer is too high.",
    "88": "Magmon supplied -12v for the RuO buffer is too low.",
    "91": "Magnet Monitor internal temp too hot.",
    "92": "Magnet Monitor internal temp too cold.",
    "100": "The heater has been on too long.",
    "101": "The He pressure is not changing.",
    "102": "The RfUnblank signal from the system cabinet is always on.",
    "110": "Coolant Leak Detected.",
    "120": "The magnet field reed switch is open.",
    "121": "Compressor 1 is not running.",
    "122": "Compressor 1 reports a tripped fuse.",
    "123": "Compressor 1 reports an overtemp shutdown.",
    "124": "Compressor 1 reports a low He pressure shutdown.",
    "125": "No 24v supply from compressor 1.",
    "126": "Compressor 1 reports a klixon error.",
    "127": "Compressor 2 is not running.",
    "128": "Compressor 2 reports a tripped fuse.",
    "129": "Compressor 2 reports an overtemp shutdown.",
    "130": "Compressor 2 reports a low He pressure shutdown.",
    "131": "No 24v supply from compressor 2.",
    "132": "Compressor 2 reports a klixon error.",
}

def notify_error_report(er: ErrorReport):
    """
    Envía un correo a todos los usuarios activos cuando se crea una alarma (ErrorReport).
    """
    try:
        # Usuarios activos con email definido
        users = User.objects.all() \
                            .exclude(email__isnull=True) \
                            .exclude(email__exact='')

        emails = [u.email for u in users]
        if not emails:
            logger.warning("No hay usuarios con email para notificar alarmas")
            return

        device_id = er.device.member_id if er.device else "Desconocido"

        subject = f"[MRI Monitor] Nueva alarma en {device_id} ({er.error_code})"

        # Descripción “estándar” de código si existe en el mapa
        description = ERROR_CODE_MAP.get(er.error_code, "")

        lines = [
            "Se ha registrado una nueva alarma en el sistema.",
            "",
            f"Dispositivo: {device_id}",
            f"Código de alarma: {er.error_code}",
        ]

        if er.abstract:
            lines.append(f"Resumen: {er.abstract}")

        if description:
            lines.append(f"Descripción estándar: {description}")

        if er.detail:
            lines.append(f"Detalle: {er.detail}")

        lines.append(f"Fecha/hora: {er.generated_at or er.reported_at}")

        message = "\n".join(lines)

        # Usamos el DEFAULT_FROM_EMAIL o el primer email como fallback
        from_email = getattr(settings, "DEFAULT_FROM_EMAIL", None) or emails[0]

        # Ponemos todos los destinatarios en BCC para no exponer sus correos entre ellos
        email = EmailMessage(
            subject=subject,
            body=message,
            from_email=from_email,
            to=[from_email],
            bcc=emails,
        )

        email.send(fail_silently=False)
        logger.info("Enviadas notificaciones de alarma a %d usuarios", len(emails))

    except Exception:
        logger.exception("Error enviando emails de nueva alarma")


def _local_name(tag):
    return tag.split('}')[-1] if '}' in tag else tag

def _get_request_header_memberid(root):
    # busca Header -> RequestHeader -> SecurityContext -> Credentials -> MemberId
    for ch in root:
        if _local_name(ch.tag) == 'Header':
            for rh in ch:
                if _local_name(rh.tag) == 'RequestHeader':
                    # buscar SecurityContext -> Credentials -> MemberId
                    for rr in rh:
                        if _local_name(rr.tag) == 'SecurityContext':
                            for sc in rr:
                                if _local_name(sc.tag) == 'Credentials':
                                    for cred in sc:
                                        if _local_name(cred.tag) == 'MemberId':
                                            return cred.text.strip() if cred.text else None
    return None

def _find_properties_and_generated_at(body):
    props = {}
    gen_at = None
    for op in body:
        for child in op:
            if _local_name(child.tag) == 'Properties':
                gen_at = child.get('generatedAt')
                for p in child:
                    if _local_name(p.tag) == 'Property':
                        name = p.get('name')
                        value = p.text if p.text is not None else ''
                        props[name] = value
                return props, gen_at
    return props, gen_at

def _parse_fault(body):
    # busca Fault dentro del body y devuelve fields
    for op in body:
        for child in op:
            if _local_name(child.tag) == 'Fault':
                out = {}
                for f in child:
                    out[_local_name(f.tag)] = f.text
                return out
    return {}

def _normalize_error_code(code_raw: str) -> str:
    """Convierte '025' -> '25', '00' -> '0'"""
    if not code_raw:
        return ''
    code = code_raw.strip()
    # eliminar prefijo zeros
    try:
        # si es numérico
        n = int(code)
        return str(n)
    except Exception:
        return code

@csrf_exempt
def soap_endpoint(request):
    raw = request.body.decode('utf-8', errors='replace')
    logger.debug("RAW SOAP incoming (preview): %s", raw[:2000])

    # parsear XML
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as e:
        logger.exception("XML parse error: %s", e)
        fault = "<Fault>Malformed XML</Fault>"
        return HttpResponse(fault, status=400, content_type='text/xml')

    # extraer member_id del header (si existe)
    member_id = _get_request_header_memberid(root)
    device = None
    if member_id:
        device, created = Device.objects.get_or_create(member_id=member_id)
        if created:
            logger.info("Created new Device for MemberId=%s", member_id)
    else:
        logger.warning("No MemberId found in SOAP header; device association will be None")

    # buscar Body
    body = None
    for ch in root:
        if _local_name(ch.tag) == 'Body':
            body = ch
            break
    if body is None:
        logger.warning("No SOAP Body present")
        return HttpResponse("", content_type='text/plain', status=200)

    # detectar operación (mirar primer hijo del Body)
    operation_elem = None
    for op in body:
        operation_elem = op
        break
    operation = _local_name(operation_elem.tag) if operation_elem is not None else None
    logger.debug("SOAP operation detected: %s", operation)

    # --- pushProperties: guardar sensores y lecturas asociados a device ---
    if operation == 'pushProperties':
        props, generated_at = _find_properties_and_generated_at(body)
        logger.info("pushProperties: %d props, generatedAt=%s, device=%s", len(props), generated_at, member_id)

        if member_id:
            handle_push_properties(member_id, props, generated_at)
        else:
            logger.warning("pushProperties received without MemberId. Skipping.")

        resp = HttpResponse("", content_type='text/plain', status=200)
        resp['Content-Length'] = '0'
        return resp


    # --- submitFault: crear ErrorReport asociado al device, guardar detail/abstract/generatedAt/rawXML ---
    if operation == 'submitFault':
        fault = _parse_fault(body)  # dict con keys MemberId, ErrorCode, Abstract, Detail, GeneratedAt...
        logger.info("submitFault parsed fault: %s", fault)
        code_raw = fault.get('ErrorCode') or fault.get('Error') or ''
        code_norm = _normalize_error_code(code_raw)
        abstract = fault.get('Abstract') or ''
        detail = fault.get('Detail') or ''
        gen = fault.get('GeneratedAt') or fault.get('generatedAt') or None

        # descripción legible si existe en map
        description = ERROR_CODE_MAP.get(code_norm, '')

        try:
            er = ErrorReport.objects.create(
                device=device,
                sensor=None,
                error_code=code_norm,
                abstract=(abstract or ''),
                detail=(detail or ''),
                generated_at=(datetime.fromisoformat(gen.replace('Z', '+00:00')) if gen else None),
                raw_xml=raw
            )
            logger.info("Created ErrorReport id=%s code=%s device=%s", er.id, code_norm, member_id)

            notify_error_report(er)
        except Exception as e:
            logger.exception("Failed to create ErrorReport for submitFault: %s", e)
            # fallback: log in file/console and return empty 200 like server_soap.py
            resp = HttpResponse("", content_type='text/plain', status=200)
            resp['Content-Length'] = '0'
            return resp

        # server_soap.py behaviour: empty 200 after submitFault
        resp = HttpResponse("", content_type='text/plain', status=200)
        resp['Content-Length'] = '0'
        return resp

    # default: behavior unchanged
    logger.info("SOAP operation %s not handled explicitly; returning empty OK", operation)
    resp = HttpResponse("", content_type='text/plain', status=200)
    resp['Content-Length'] = '0'
    return resp

def handle_push_properties(member_id: str, properties: Dict[str, str], generated_at: Optional[str] = None):
    """
    Ensure that for every pushProperties we write a SensorReading for ALL sensors of the device
    + apply normalizations + compressor translation + threshold-based alerts.
    """

    # parse timestamp
    ts = None
    if generated_at:
        try:
            ts = parse_datetime(generated_at)
            if ts is None:
                ts = timezone.now()
            elif timezone.is_naive(ts):
                ts = timezone.make_aware(ts, timezone.get_default_timezone())
        except Exception:
            ts = timezone.now()
    else:
        ts = timezone.now()

    with transaction.atomic():

        device, _ = Device.objects.get_or_create(member_id=member_id)

        sensors_qs = Sensor.objects.filter(device=device)
        sensors_by_code = { (s.code or "").upper(): s for s in sensors_qs }
        sensors_by_id = { s.id: s for s in sensors_qs }

        snapshot = {}
        for s in sensors_qs:
            key = (getattr(s, "code", None) or getattr(s, "name", None) or str(s.id)).upper()
            snapshot[key] = getattr(s, "last_value", None)

        incoming_keys = set()

        for pname, raw_value in properties.items():
            if not pname:
                continue

            code = pname.strip().upper()
            incoming_keys.add(code)

            # ---- 1) Normalize using sensors.json
            if code in SENSOR_CODE_MAP:
                norm_name, norm_unit, _ = SENSOR_CODE_MAP[code]
            else:
                norm_name = code
                norm_unit = ""

            sensor = sensors_by_code.get(code)

            if not sensor:
                sensor = Sensor.objects.create(
                    device=device,
                    code=code,
                    name=norm_name,
                    type="measured"
                )
                sensors_by_code[code] = sensor

            # CPR1 translation
            if code == "CPR1":
                human = COMPRESSOR_CODES.get(str(raw_value).strip(), None)
                if human:
                    raw_value = human

            snapshot[code] = raw_value

            # Update last_value
            try:
                sensor.last_value = str(raw_value)
            except Exception:
                sensor.last_value = None
            sensor.timestamp = ts
            sensor.save()

            # ---- 2) Threshold-based notifications
            if code in THRESHOLDS:
                try:
                    val = float(raw_value)
                except:
                    val = None

                if val is not None:

                    limits = THRESHOLDS[code]
                    # Format example: "critical: > 27°C"
                    crit = str(limits.get("critical", "")).replace("°C", "").replace(">", "").strip()
                    warn = str(limits.get("warning", "")).replace("°C", "").replace(">", "").strip()

                    try:
                        crit_val = float(crit)
                        warn_val = float(warn)
                    except:
                        crit_val = warn_val = None

                    if crit_val and val > crit_val:
                        er = ErrorReport.objects.create(
                            device=device,
                            sensor=sensor,
                            error_code=f"{code}_CRIT",
                            abstract="CRITICAL",
                            detail=f"{sensor.name} exceeded critical threshold: {val}",
                            generated_at=ts,
                            raw_xml="AUTO_THRESHOLD"
                        )
                        notify_error_report(er)

                    elif warn_val and val > warn_val:
                        er = ErrorReport.objects.create(
                            device=device,
                            sensor=sensor,
                            error_code=f"{code}_WARN",
                            abstract="WARNING",
                            detail=f"{sensor.name} above warning threshold: {val}",
                            generated_at=ts,
                            raw_xml="AUTO_THRESHOLD"
                        )
                        notify_error_report(er)

        # ---- 3) Create SensorReadings snapshot for all sensors
        readings_to_create = []

        for code, sensor in sensors_by_code.items():
            val = snapshot.get(code)

            # Normalizar: si val es None -> value_text = ''
            value_numeric = None
            value_text = ""

            if val is None:
                # no value: keep numeric None and text empty
                value_text = ""
            else:
                try:
                    # intentar parsear a float
                    value_numeric = float(val)
                    # cuando es numérico, dejamos value_text como cadena vacía (NOT NULL en DB)
                    value_text = ""
                except Exception:
                    # si no es convertible a float, guardamos la representación textual
                    value_numeric = None
                    # asegurarnos que value_text no sea None
                    value_text = str(val) if val is not None else ""
            
            # 👇 AQUÍ marcamos si este sensor ha venido en el XML (update real)
            source_flag = "PUSH" if code in incoming_keys else "SNAPSHOT"

            readings_to_create.append(
                SensorReading(
                    device=device,
                    sensor=sensor,
                    value_numeric=value_numeric,
                    value_text=value_text,
                    generated_at=ts,
                    received_at=timezone.now(),
                    source_member=source_flag, # indica si fue push o snapshot
                )
            )

        SensorReading.objects.bulk_create(readings_to_create)

    return True