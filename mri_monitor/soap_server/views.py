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
    # include as many entries as you need; example:
    "0": "No Error.",
    "1": "He Level too high.",
    "2": "He Level too low.",
    # ... (completa desde MO-ERROR CODES) ...
    "25": "Vessel pressure too high.",
    "101": "The He pressure is not changing.",
    # etc.
}

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
                        ErrorReport.objects.create(
                            device=device,
                            sensor=sensor,
                            error_code=f"{code}_CRIT",
                            abstract="CRITICAL",
                            detail=f"{sensor.name} exceeded critical threshold: {val}",
                            generated_at=ts,
                            raw_xml="AUTO_THRESHOLD"
                        )

                    elif warn_val and val > warn_val:
                        ErrorReport.objects.create(
                            device=device,
                            sensor=sensor,
                            error_code=f"{code}_WARN",
                            abstract="WARNING",
                            detail=f"{sensor.name} above warning threshold: {val}",
                            generated_at=ts,
                            raw_xml="AUTO_THRESHOLD"
                        )

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