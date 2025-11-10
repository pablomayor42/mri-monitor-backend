# mri_monitor/soap_server/views.py
import logging
from datetime import datetime
from xml.etree import ElementTree as ET
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone

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
    "RF": ("RF", "", "RF Flag"),
    "CPR1": ("CPR1", "", "Compressor1 Status Code"),
    "CDC1": ("CDC1", "", "Compressor1 Duty Cycle"),
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
        saved = 0
        for raw_code, raw_value in props.items():
            # mapear nombre
            mapping = SENSOR_CODE_MAP.get(raw_code)
            if mapping:
                key = mapping[0]
            else:
                key = raw_code  # si no hay mapping usa raw code

            # obtener o crear sensor asociado al device
            if device:
                sensor, screated = Sensor.objects.get_or_create(device=device, name=key, defaults={'code': raw_code, 'type': 'measured'})
            else:
                # si no hay device, crear sensor con device=None no permitido por FK -> omitimos
                logger.warning("No device for sensor %s; skipping (member_id missing)", raw_code)
                continue

            # parseo numérico seguro
            value_text = (raw_value or '').strip()
            value_numeric = None
            if value_text != '':
                try:
                    value_numeric = float(value_text)
                except Exception:
                    value_numeric = None

            # actualizar sensor.last_value si es numérico
            if value_numeric is not None:
                sensor.last_value = value_numeric
            sensor.code = raw_code
            sensor.timestamp = timezone.now()
            sensor.save()

            # crear lectura histórica
            gen_dt = None
            if generated_at:
                try:
                    gen_dt = datetime.fromisoformat(generated_at.replace('Z', '+00:00'))
                except Exception:
                    gen_dt = None

            SensorReading.objects.create(
                device=device,
                sensor=sensor,
                value_text=value_text,
                value_numeric=value_numeric,
                source_member=(member_id or ''),
                generated_at=gen_dt
            )
            saved += 1
        logger.info("pushProperties saved %d readings for device %s", saved, member_id)

        # server_soap.py behavior: respond with empty 200 for pushProperties
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
