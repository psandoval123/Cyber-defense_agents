"""Herramientas del agente de respuesta (Lab 2).

Contratos explícitos (docs/02_arquitectura.md). El agente DECIDE y ORDENA; el
firewall (enforcer) EJECUTA. Por eso `bloquear_ip` no toca la red: solo escribe
una ORDEN que el firewall aplica, con autorización, resultado y evidencia.

  - consultar_incidente   -> identifica la IP atacante desde las alertas del sensor
  - bloquear_ip           -> emite la orden de bloqueo (acción con impacto)
  - verificar_contencion  -> confirma con el firewall que el bloqueo está activo
  - generar_informe_respuesta -> informe de respuesta con trazabilidad
"""

from __future__ import annotations

import json
import re
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

EVE_PATH = Path("/output/suricata/eve.json")
ORDENES_DIR = Path("/output/ordenes")
ESTADO_FIREWALL = Path("/output/firewall/estado.json")
INFORMES_DIR = Path("/output/informes_respuesta")

_RE_TECNICA = re.compile(r"\[(T\d{4}(?:\.\d{3})?)\]")


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _ahora() -> str:
    return datetime.now(timezone.utc).isoformat()


def consultar_incidente(_args: dict | None = None) -> dict:
    """Analiza las alertas del sensor e identifica el incidente: la IP de origen
    más activa (el atacante), las técnicas MITRE observadas y la ventana temporal.
    """
    if not EVE_PATH.exists():
        return {"hay_incidente": False, "nota": "No hay alertas (eve.json no existe)."}

    por_ip: Counter[str] = Counter()
    tecnicas: set[str] = set()
    total = 0
    primera = ultima = None

    with EVE_PATH.open("r", encoding="utf-8") as fh:
        for linea in fh:
            linea = linea.strip()
            if not linea:
                continue
            try:
                ev = json.loads(linea)
            except json.JSONDecodeError:
                continue
            if ev.get("event_type") != "alert":
                continue
            total += 1
            src = ev.get("src_ip")
            if src:
                por_ip[src] += 1
            m = _RE_TECNICA.search(ev.get("alert", {}).get("signature", ""))
            if m:
                tecnicas.add(m.group(1))
            ts = ev.get("timestamp")
            if ts:
                primera = ts if primera is None else min(primera, ts)
                ultima = ts if ultima is None else max(ultima, ts)

    if not por_ip:
        return {"hay_incidente": False, "nota": "Sin alertas de tipo 'alert'."}

    ip_atacante, conteo = por_ip.most_common(1)[0]
    return {
        "hay_incidente": True,
        "ip_atacante": ip_atacante,
        "alertas_de_esa_ip": conteo,
        "total_alertas": total,
        "tecnicas": sorted(tecnicas),
        "primera_alerta": primera,
        "ultima_alerta": ultima,
    }


def bloquear_ip(args: dict) -> dict:
    """Emite una ORDEN de bloqueo para el firewall. args: {"ip": "172.30.0.3"}.

    No aplica nada directamente: escribe la orden que el enforcer ejecutará.
    """
    ip = (args or {}).get("ip", "")
    ORDENES_DIR.mkdir(parents=True, exist_ok=True)
    oid = f"ORD-{_ts()}"
    orden = {
        "id": oid,
        "ip": ip,
        "accion": "block",
        "estado": "pendiente",
        "creado": _ahora(),
        "origen": "response-agent-lab2",
    }
    (ORDENES_DIR / f"{oid}.json").write_text(
        json.dumps(orden, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"ok": True, "orden_id": oid, "ip": ip, "estado": "pendiente"}


def verificar_contencion(args: dict) -> dict:
    """Confirma con el firewall que la IP quedó bloqueada. args: {"ip": "..."}.

    Consulta el estado publicado por el enforcer (espera hasta ~15 s a que aplique).
    """
    ip = (args or {}).get("ip", "")
    for _ in range(15):
        if ESTADO_FIREWALL.exists():
            try:
                estado = json.loads(ESTADO_FIREWALL.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                estado = {}
            if ip in estado.get("ips_bloqueadas", []):
                return {
                    "contenido": True,
                    "ip": ip,
                    "confirmado_por": "firewall",
                    "momento": estado.get("actualizado"),
                    "regla_activa": [r for r in estado.get("iptables_input", [])
                                     if ip in r],
                }
        time.sleep(1)
    return {"contenido": False, "ip": ip,
            "nota": "El firewall no confirmó el bloqueo en el tiempo esperado."}


def generar_informe_respuesta(args: dict) -> dict:
    """Escribe el informe de respuesta. args esperados:
    {"titulo","ip","tecnicas":[],"accion","autorizacion","resultado",
     "mttr_s","resumen"}.
    """
    args = args or {}
    INFORMES_DIR.mkdir(parents=True, exist_ok=True)
    ts = _ts()
    tecnicas = args.get("tecnicas", [])
    lineas = [
        f"# Informe de respuesta — {args.get('titulo', 'Contención de incidente')}",
        "",
        f"- **Fecha:** {_ahora()}",
        f"- **IP contenida:** {args.get('ip', 'n/d')}",
        f"- **Acción:** {args.get('accion', 'bloqueo de IP (iptables DROP)')}",
        f"- **Autorización:** {args.get('autorizacion', 'n/d')}",
        f"- **Resultado:** {args.get('resultado', 'n/d')}",
        f"- **MTTR:** {args.get('mttr_s', 'n/d')} s",
        f"- **Generado por:** agente de respuesta (Lab 2, LLM local)",
        "",
        "## Resumen",
        "",
        args.get("resumen", "(sin resumen)"),
        "",
        "## Técnicas MITRE ATT&CK del incidente",
        "",
    ]
    lineas += [f"- `{t}`" for t in tecnicas] or ["- (ninguna)"]
    lineas += ["", "## Reversibilidad", "",
               "El bloqueo es reversible: `docker compose exec response_agent "
               "python3 response_agent.py --rollback` o eliminando la regla en "
               "el firewall. Queda registrado en `output/ordenes/`.", ""]
    ruta = INFORMES_DIR / f"informe-respuesta-{ts}.md"
    ruta.write_text("\n".join(lineas), encoding="utf-8")
    return {"ok": True, "ruta": str(ruta)}


HERRAMIENTAS = {
    "consultar_incidente": (
        consultar_incidente,
        "Identifica la IP atacante y las técnicas desde las alertas. Sin argumentos.",
    ),
    "bloquear_ip": (
        bloquear_ip,
        'Emite la orden de bloqueo de una IP. args: {"ip":"172.30.0.3"}. '
        "ACCIÓN CON IMPACTO: requiere aprobación previa.",
    ),
    "verificar_contencion": (
        verificar_contencion,
        'Confirma que el firewall aplicó el bloqueo. args: {"ip":"172.30.0.3"}.',
    ),
    "generar_informe_respuesta": (
        generar_informe_respuesta,
        'Escribe el informe de respuesta. args: {"titulo","ip","tecnicas":[],'
        '"accion","autorizacion","resultado","mttr_s","resumen"}.',
    ),
}


def catalogo_para_prompt() -> str:
    return "\n".join(f"- {nombre}: {desc}" for nombre, (_, desc) in HERRAMIENTAS.items())
