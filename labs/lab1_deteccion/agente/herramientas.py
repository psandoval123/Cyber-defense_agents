"""Herramientas del agente de detección (Lab 1).

Contratos explícitos (ver docs/02_arquitectura.md): cada herramienta recibe
argumentos tipados, hace UNA cosa y devuelve un resultado serializable. El
agente las invoca por nombre a través del ciclo ReAct.

  - consultar_alertas  -> "consultar SIEM" (lee las alertas del sensor)
  - enriquecer_attack  -> enriquecimiento con MITRE ATT&CK
  - crear_caso         -> creación de caso (incidente)
  - generar_informe    -> informe y evidencia

Ninguna herramienta ejecuta acciones con impacto: en el Lab 1 el agente solo
observa, clasifica y documenta (límite definido en la arquitectura).
"""

from __future__ import annotations

import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from attack_map import buscar_tecnica

EVE_PATH = Path("/output/suricata/eve.json")
CASOS_DIR = Path("/output/casos")
INFORMES_DIR = Path("/output/informes")

# Extrae el identificador de técnica embebido en el msg de la regla: "... [T1046]".
_RE_TECNICA = re.compile(r"\[(T\d{4}(?:\.\d{3})?)\]")


def _ahora_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def consultar_alertas(_args: dict | None = None) -> dict:
    """Lee las alertas del sensor (eve.json) y las resume.

    Devuelve el total de alertas, un agregado por firma (con su técnica ATT&CK
    sugerida, los IPs implicados y la primera/última marca de tiempo) y las IPs
    de origen observadas. Es la "consulta al SIEM" del laboratorio.
    """
    if not EVE_PATH.exists():
        return {"total_alertas": 0, "firmas": [], "nota": "Aún no hay alertas (eve.json no existe)."}

    firmas: dict[str, dict] = {}
    ips_origen: Counter[str] = Counter()
    total = 0

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
            firma = ev.get("alert", {}).get("signature", "desconocida")
            src = ev.get("src_ip", "?")
            dst = ev.get("dest_ip", "?")
            ts = ev.get("timestamp", "")
            ips_origen[src] += 1

            m = _RE_TECNICA.search(firma)
            tecnica = m.group(1) if m else None

            if firma not in firmas:
                firmas[firma] = {
                    "firma": firma,
                    "tecnica_sugerida": tecnica,
                    "conteo": 0,
                    "src_ips": set(),
                    "dest_ips": set(),
                    "primera_vez": ts,
                    "ultima_vez": ts,
                }
            reg = firmas[firma]
            reg["conteo"] += 1
            reg["src_ips"].add(src)
            reg["dest_ips"].add(dst)
            if ts:
                reg["primera_vez"] = min(reg["primera_vez"] or ts, ts)
                reg["ultima_vez"] = max(reg["ultima_vez"] or ts, ts)

    # Convierte sets a listas para serializar.
    resumen_firmas = []
    for reg in firmas.values():
        reg = dict(reg)
        reg["src_ips"] = sorted(reg["src_ips"])
        reg["dest_ips"] = sorted(reg["dest_ips"])
        resumen_firmas.append(reg)

    return {
        "total_alertas": total,
        "firmas_distintas": len(resumen_firmas),
        "firmas": resumen_firmas,
        "ips_origen": dict(ips_origen),
    }


def enriquecer_attack(args: dict) -> dict:
    """Devuelve la ficha MITRE ATT&CK de una técnica. args: {"tecnica": "T1046"}."""
    tid = (args or {}).get("tecnica", "")
    return buscar_tecnica(tid)


def crear_caso(args: dict) -> dict:
    """Crea un caso de incidente en disco. args esperados:
    {"titulo", "severidad", "tecnicas": [..], "observables": [..], "resumen"}.
    """
    args = args or {}
    CASOS_DIR.mkdir(parents=True, exist_ok=True)
    ts = _ahora_ts()
    caso = {
        "id": f"CASO-{ts}",
        "creado": datetime.now(timezone.utc).isoformat(),
        "titulo": args.get("titulo", "Incidente de reconocimiento"),
        "severidad": args.get("severidad", "media"),
        "tecnicas": args.get("tecnicas", []),
        "observables": args.get("observables", []),
        "resumen": args.get("resumen", ""),
        "estado": "abierto",
        "origen": "agente-deteccion-lab1",
    }
    ruta = CASOS_DIR / f"{caso['id']}.json"
    ruta.write_text(json.dumps(caso, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"ok": True, "id": caso["id"], "ruta": str(ruta)}


def generar_informe(args: dict) -> dict:
    """Escribe el informe final de incidente en Markdown. args esperados:
    {"titulo", "veredicto", "tecnicas": [..], "observables": [..],
     "recomendaciones": [..], "resumen"}.
    """
    args = args or {}
    INFORMES_DIR.mkdir(parents=True, exist_ok=True)
    ts = _ahora_ts()
    tecnicas = args.get("tecnicas", [])
    observables = args.get("observables", [])
    recomendaciones = args.get("recomendaciones", [])

    lineas = [
        f"# Informe de incidente — {args.get('titulo', 'Reconocimiento detectado')}",
        "",
        f"- **Fecha:** {datetime.now(timezone.utc).isoformat()}",
        f"- **Veredicto:** {args.get('veredicto', 'n/d')}",
        f"- **Generado por:** agente de detección (Lab 1, LLM local)",
        "",
        "## Resumen",
        "",
        args.get("resumen", "(sin resumen)"),
        "",
        "## Técnicas MITRE ATT&CK",
        "",
    ]
    lineas += [f"- `{t}`" for t in tecnicas] or ["- (ninguna)"]
    lineas += ["", "## Observables", ""]
    lineas += [f"- {o}" for o in observables] or ["- (ninguno)"]
    lineas += ["", "## Recomendaciones defensivas", ""]
    lineas += [f"- {r}" for r in recomendaciones] or ["- (ninguna)"]
    lineas += [""]

    ruta = INFORMES_DIR / f"informe-{ts}.md"
    ruta.write_text("\n".join(lineas), encoding="utf-8")
    return {"ok": True, "ruta": str(ruta)}


# Registro de herramientas: nombre -> (callable, descripción para el prompt).
HERRAMIENTAS = {
    "consultar_alertas": (
        consultar_alertas,
        "Lee y resume las alertas del sensor Suricata. Sin argumentos.",
    ),
    "enriquecer_attack": (
        enriquecer_attack,
        'Devuelve la ficha MITRE ATT&CK de una técnica. args: {"tecnica":"T1046"}.',
    ),
    "crear_caso": (
        crear_caso,
        'Crea un caso de incidente. args: {"titulo","severidad","tecnicas":[],'
        '"observables":[],"resumen"}.',
    ),
    "generar_informe": (
        generar_informe,
        'Escribe el informe final. args: {"titulo","veredicto","tecnicas":[],'
        '"observables":[],"recomendaciones":[],"resumen"}.',
    ),
}


def catalogo_para_prompt() -> str:
    """Texto con las herramientas disponibles para incluir en el system prompt."""
    return "\n".join(f"- {nombre}: {desc}" for nombre, (_, desc) in HERRAMIENTAS.items())
