"""Agente de respuesta del Laboratorio 2 (lado AZUL).

Patrón ReAct sobre un LLM local (Ollama). Toma el incidente de reconocimiento
(las alertas del sensor), identifica la IP atacante, PROPONE el bloqueo, PIDE
APROBACIÓN humana (intervención manual ante acciones con impacto), emite la
orden al firewall, verifica la contención y documenta la respuesta con MTTR.

El agente DECIDE y ORDENA; el firewall EJECUTA. El agente no tiene privilegios
de red: `bloquear_ip` solo escribe una orden (output/ordenes/) que el enforcer
aplica de forma reversible y auditada.

Modos:
  (sin args)   corrida normal de respuesta.
  --rollback   revierte los bloqueos activos (para reiniciar la demo).
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
import ollama

from herramientas import (HERRAMIENTAS, catalogo_para_prompt, ORDENES_DIR,
                          ESTADO_FIREWALL)

load_dotenv()

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://ollama:11434")
MODELO = os.getenv("LAB_MODELO", "llama3.2:3b")
MAX_ITER = int(os.getenv("LAB_MAX_ITERACIONES", "12"))
TEMPERATURA = float(os.getenv("LAB_TEMPERATURA", "0"))
AUTO_APROBAR = os.getenv("LAB_AUTO_APROBAR", "false").lower() in {"1", "true", "si", "sí", "yes"}

TRAZAS_DIR = Path("/output/trazas_respuesta")
METRICAS_DIR = Path("/output/metricas")

SYSTEM_PROMPT = f"""Eres un agente de respuesta a incidentes de un SOC. Un sensor
IDS ya detectó un reconocimiento. Tu misión es CONTENER al atacante bloqueando
su IP en el firewall, de forma segura, verificada y documentada.

Trabajas en ciclos ReAct. En CADA turno respondes EXCLUSIVAMENTE con un objeto
JSON válido, sin texto adicional, con una de estas formas:

1) Usar una herramienta:
{{"pensamiento": "<razonamiento breve>",
  "accion": {{"herramienta": "<nombre>", "args": {{...}}}}}}

2) Terminar (tras verificar la contención y generar el informe):
{{"pensamiento": "<cierre>",
  "final": {{"ip_contenida": "<ip>", "tecnicas": ["T1046", ...],
             "contenido": true, "resumen": "<2-3 frases>"}}}}

Herramientas disponibles:
{catalogo_para_prompt()}

Procedimiento OBLIGATORIO (en orden, sin repetir herramientas):
1. `consultar_incidente` para obtener la IP atacante y las técnicas.
2. `bloquear_ip` con esa IP (el sistema pedirá aprobación humana antes de aplicar).
3. `verificar_contencion` con la misma IP.
4. `generar_informe_respuesta` con la acción, la autorización y el resultado.
5. Responde con `final`.
No inventes IPs: usa la que devuelva `consultar_incidente`."""


def ahora_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_ts(valor: str | None) -> datetime | None:
    if not valor:
        return None
    valor = valor.replace("Z", "+00:00")
    valor = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", valor)  # +0000 -> +00:00
    try:
        return datetime.fromisoformat(valor)
    except ValueError:
        return None


def extraer_json(texto: str) -> dict | None:
    texto = texto.strip()
    try:
        return json.loads(texto)
    except json.JSONDecodeError:
        pass
    m = re.search(r"\{.*\}", texto, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            return None
    return None


def pedir_aprobacion(ip: str) -> bool:
    """Compuerta human-in-the-loop antes de una acción con impacto."""
    print("\n" + "!" * 70)
    print(f"  SOLICITUD DE APROBACIÓN — el agente propone BLOQUEAR la IP {ip}")
    print("!" * 70)
    if AUTO_APROBAR:
        print("  [LAB_AUTO_APROBAR=true] Aprobación automática.")
        return True
    try:
        resp = input("  ¿Aprobar el bloqueo? [s/N]: ").strip().lower()
    except EOFError:
        resp = ""
    return resp in {"s", "si", "sí", "y", "yes"}


def rollback() -> int:
    """Revierte los bloqueos activos emitiendo órdenes 'unblock'."""
    if not ESTADO_FIREWALL.exists():
        print("[rollback] No hay estado de firewall; nada que revertir.")
        return 0
    estado = json.loads(ESTADO_FIREWALL.read_text(encoding="utf-8"))
    ips = estado.get("ips_bloqueadas", [])
    if not ips:
        print("[rollback] No hay IPs bloqueadas.")
        return 0
    ORDENES_DIR.mkdir(parents=True, exist_ok=True)
    for ip in ips:
        oid = f"ORD-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-unblock"
        (ORDENES_DIR / f"{oid}.json").write_text(json.dumps({
            "id": oid, "ip": ip, "accion": "unblock", "estado": "pendiente",
            "creado": ahora_iso(), "origen": "response-agent-lab2",
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[rollback] Orden de desbloqueo emitida para {ip}")
    print("[rollback] Espera unos segundos a que el firewall las aplique.")
    return 0


def main() -> int:
    if "--rollback" in sys.argv:
        return rollback()

    TRAZAS_DIR.mkdir(parents=True, exist_ok=True)
    METRICAS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    traza_path = TRAZAS_DIR / f"traza-{ts}.jsonl"
    cliente = ollama.Client(host=OLLAMA_HOST)

    print("=" * 70)
    print(f"  Agente de respuesta — Lab 2 | modelo: {MODELO} @ {OLLAMA_HOST}")
    print(f"  Aprobación: {'AUTOMÁTICA' if AUTO_APROBAR else 'MANUAL (human-in-the-loop)'}")
    print("=" * 70)

    mensajes = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": "Contén el incidente de reconocimiento detectado."},
    ]

    herramientas_usadas: list[str] = []
    estado = {
        "primera_alerta": None, "ip_atacante": None, "tecnicas": [],
        "aprobacion": "n/a", "ip_bloqueada": None,
        "t_bloqueo_ordenado": None, "t_bloqueo_efectivo": None,
        "contencion_ok": False,
    }
    inicio = time.time()
    t_inicio_iso = ahora_iso()

    with traza_path.open("w", encoding="utf-8") as traza:
        def anotar(**c):
            c.setdefault("timestamp", ahora_iso())
            traza.write(json.dumps(c, ensure_ascii=False) + "\n")
            traza.flush()

        anotar(evento="inicio", modelo=MODELO, auto_aprobar=AUTO_APROBAR)

        for paso in range(1, MAX_ITER + 1):
            try:
                resp = cliente.chat(model=MODELO, messages=mensajes, format="json",
                                    options={"temperature": TEMPERATURA,
                                             "num_predict": 512, "num_ctx": 4096})
            except Exception as exc:  # noqa: BLE001
                print(f"\n[!] Error al consultar Ollama: {exc}")
                anotar(evento="error_llm", detalle=str(exc))
                return 1

            obj = extraer_json(resp["message"]["content"])
            if obj is None:
                anotar(evento="parse_error", paso=paso)
                mensajes.append({"role": "user", "content": "Responde SOLO con el JSON indicado."})
                continue

            pensamiento = obj.get("pensamiento", "")
            print(f"\n[paso {paso}] 🧠 {pensamiento}")
            mensajes.append({"role": "assistant", "content": json.dumps(obj, ensure_ascii=False)})

            if "final" in obj:
                anotar(evento="final", paso=paso, final=obj.get("final"))
                print(f"\n[✓] {obj.get('final')}")
                break

            accion = obj.get("accion") or {}
            nombre = accion.get("herramienta", "")
            args = accion.get("args", {}) or {}
            if nombre not in HERRAMIENTAS:
                anotar(evento="herramienta_invalida", paso=paso, nombre=nombre)
                mensajes.append({"role": "user", "content": f"Herramienta '{nombre}' no existe."})
                continue

            # --- Compuerta de aprobación para acciones con impacto ---
            if nombre == "bloquear_ip":
                ip = args.get("ip", "")
                aprobado = pedir_aprobacion(ip)
                estado["aprobacion"] = ("auto" if AUTO_APROBAR else "manual") if aprobado else "denegada"
                anotar(evento="aprobacion", ip=ip, aprobado=aprobado, modo=estado["aprobacion"])
                if not aprobado:
                    print("    ⛔ Bloqueo NO autorizado por el operador.")
                    mensajes.append({"role": "user", "content": "Observación: el "
                        "operador NO autorizó el bloqueo. Genera el informe indicando "
                        "que la contención quedó pendiente de aprobación y responde con final."})
                    continue
                estado["t_bloqueo_ordenado"] = ahora_iso()

            print(f"    ⚙️ {nombre}({json.dumps(args, ensure_ascii=False)})")
            funcion = HERRAMIENTAS[nombre][0]
            try:
                observacion = funcion(args)
            except Exception as exc:  # noqa: BLE001
                observacion = {"error": str(exc)}
            herramientas_usadas.append(nombre)
            print(f"    └─ {json.dumps(observacion, ensure_ascii=False)[:400]}")
            anotar(evento="accion", paso=paso, herramienta=nombre, args=args,
                   observacion=observacion)

            # Captura de datos para métricas.
            if nombre == "consultar_incidente" and observacion.get("hay_incidente"):
                estado["primera_alerta"] = observacion.get("primera_alerta")
                estado["ip_atacante"] = observacion.get("ip_atacante")
                estado["tecnicas"] = observacion.get("tecnicas", [])
            if nombre == "verificar_contencion" and observacion.get("contenido"):
                estado["contencion_ok"] = True
                estado["ip_bloqueada"] = observacion.get("ip")
                estado["t_bloqueo_efectivo"] = observacion.get("momento") or ahora_iso()

            mensajes.append({"role": "user", "content": "Observación: "
                             + json.dumps(observacion, ensure_ascii=False)})

            # Cierre anticipado: con el informe ya generado, la tarea está completa.
            if "generar_informe_respuesta" in herramientas_usadas:
                anotar(evento="final_auto", paso=paso)
                print("\n[✓] Respuesta completada (cierre automático).")
                break
        else:
            print("\n[!] Máximo de iteraciones sin cierre.")
            anotar(evento="sin_final")

        duracion = round(time.time() - inicio, 2)
        anotar(evento="fin", duracion_s=duracion, herramientas_usadas=herramientas_usadas)

    # --- MTTR y métricas de la corrida ---
    t0 = parse_ts(estado["primera_alerta"])
    t1 = parse_ts(estado["t_bloqueo_efectivo"])
    mttr_s = round((t1 - t0).total_seconds(), 2) if (t0 and t1) else None

    metricas = {
        "corrida": ts, "modelo": MODELO, "inicio": t_inicio_iso, "fin": ahora_iso(),
        "duracion_s": duracion, "herramientas_usadas": herramientas_usadas,
        "ip_atacante": estado["ip_atacante"], "ip_bloqueada": estado["ip_bloqueada"],
        "aprobacion": estado["aprobacion"], "contencion_ok": estado["contencion_ok"],
        "tecnicas": estado["tecnicas"], "mttr_s": mttr_s,
        "primera_alerta": estado["primera_alerta"],
        "bloqueo_efectivo": estado["t_bloqueo_efectivo"],
    }
    (METRICAS_DIR / f"run-{ts}.json").write_text(
        json.dumps(metricas, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[OK] MTTR: {mttr_s} s | contención: {estado['contencion_ok']} "
          f"| métricas en output/metricas/run-{ts}.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
