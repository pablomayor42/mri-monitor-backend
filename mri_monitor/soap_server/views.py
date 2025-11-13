# mri_monitor/soap_server/views.py
import logging
from datetime import datetime
from xml.etree import ElementTree as ET
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.db import transaction
from django.utils import timezone
from typing import Dict, Optional
from django.utils.dateparse import parse_datetime

from mri_monitor.core.models import Device, Sensor, SensorReading, ErrorReport

logger = logging.getLogger('mri_monitor.soap_server')

SENSOR_CODE_MAP = {
    "A2": ("He_Level", "%", "Helium Level"),
    "A3": ("Water_Flow", "L/min", "Water Flow"),
    "A5": ("Water_Temp", "°C", "Water Temperature"),
    "A7": ("Shield_Si410", "K", "Shield Temperature (Si410)"),
    "A8": ("Recon_RuO", "K", "Recondensor RuO"),
    "A9": ("Recon_Si410", "K", "Recondensor Si410"),
    "A12": ("Coldhead_RuO", "K", "Coldhead RuO"),
    "A13": ("He_Pressure", "psi", "Helium Pressure"),
    "RF": ("RF", "", "RF Active Pluring This Minute"),
    "CPR1": ("CPR1", "", "Compressor1 Status Code"),
    "CDC1": ("CDC1", "%", "Compressor1 Duty Cycle"),
    "CDC2": ("CDC2", "%", "Compressor2 Duty Cycle"),
    "FM": ("FM", "", "Fill Mode"),
    "SM": ("SM", "", "Service Mode"),
    "HO": ("HO", "", "Heater On"),
    "HDC": ("HDC", "", "Heater Duty Cycle"),
    "F1": ("F1", "", "F1"),
    "F2": ("F2", "", "F2"),
    "F3": ("F3", "", "F3"),
    "F4": ("F4", "", "F4"),
}

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
    Ensure that for every pushProperties we write a SensorReading for ALL sensors of the device,
    using previous values for sensors not updated in this push (so graphs stay continuous).
    """
    # parse timestamp (fallback to now)
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

    # start atomic transaction
    with transaction.atomic():
        device, _ = Device.objects.get_or_create(member_id=member_id)

        # load sensors for device
        sensors_qs = Sensor.objects.filter(device=device)
        sensors_by_code = {}
        sensors_by_id = {}
        for s in sensors_qs:
            code = (getattr(s, 'code', None) or '').upper()
            sensors_by_code[code] = s
            sensors_by_id[s.id] = s

        # Build snapshot: start from sensors' last_value
        snapshot = {}
        for s in sensors_qs:
            key = (getattr(s, 'code', None) or getattr(s, 'name', None) or str(s.id)).upper()
            # prefer numeric last_value if available
            snapshot[key] = getattr(s, 'last_value', None)

        # Apply incoming properties (properties keys may be codes like 'A3' or names)
        incoming_keys = set()
        for pname, raw in properties.items():
            if not pname:
                continue
            key = pname.strip().upper()
            incoming_keys.add(key)
            sensor = sensors_by_code.get(key)
            if not sensor:
                # try to find by name (case-insensitive)
                sensor = Sensor.objects.filter(device=device, name__iexact=pname.strip()).first()
            if sensor:
                s_key = (getattr(sensor, 'code', None) or getattr(sensor, 'name', None) or str(sensor.id)).upper()
                # store raw value (string or numeric) in snapshot
                snapshot[s_key] = raw
            else:
                # Optional: create sensor dynamically if desired
                sensor = Sensor.objects.create(device=device, code=key, name=key, type='measured')
                sensors_by_code[key] = sensor
                snapshot[key] = raw

        # Prepare SensorReading objects for ALL sensors (using snapshot)
        readings_to_create = []
        sensor_updates = []
        for s_key, sensor in sensors_by_code.items():
            # Use snapshot value (might be None)
            val = snapshot.get(s_key)
            # parse numeric if possible
            value_numeric = None
            value_text = None
            if val is None:
                value_text = None
                value_numeric = None
            else:
                try:
                    value_numeric = float(str(val))
                    value_text = None
                except Exception:
                    value_numeric = None
                    value_text = str(val)

            reading = SensorReading(
                device=device,
                sensor=sensor,
                value_numeric=value_numeric,
                value_text=value_text,
                generated_at=ts,
                received_at=timezone.now()
            )
            readings_to_create.append(reading)

            # update sensor.last_value only for sensors that were part of incoming properties
            if s_key in incoming_keys:
                # set last_value to numeric if numeric else None
                if value_numeric is not None:
                    sensor.last_value = value_numeric
                else:
                    # optional: keep previous numeric; here we set to None for non-numeric
                    sensor.last_value = None
                sensor.timestamp = ts
                sensor_updates.append(sensor)

        # bulk create readings
        if readings_to_create:
            SensorReading.objects.bulk_create(readings_to_create)

        # bulk update sensors that changed
        if sensor_updates:
            Sensor.objects.bulk_update(sensor_updates, ['last_value', 'timestamp'])

    return True