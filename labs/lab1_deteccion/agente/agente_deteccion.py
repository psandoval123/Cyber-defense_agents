"""Agente de detección del Laboratorio 1 (lado AZUL).

Patrón ReAct sobre un LLM LOCAL (Ollama). El agente:
  1. Consulta las alertas del sensor Suricata.
  2. Clasifica si hay un reconocimiento en curso.
  3. Enriquece los hallazgos con MITRE ATT&CK.
  4. Abre un caso y genera un informe de incidente con recomendaciones.

Todo el ciclo (razonamiento, herramienta invocada, observación) queda
registrado en output/trazas/traza-<ts>.jsonl para trazabilidad, y las métricas
de la corrida en output/metricas/run-<ts>.json (ver docs/05_evaluacion.md).

No ejecuta acciones con impacto: solo observa, clasifica y documenta.
"""

from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
import ollama

from herramientas import HERRAMIENTAS, catalogo_para_prompt

load_dotenv()

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://ollama:11434")
MODELO = os.getenv("LAB_MODELO", "llama3.2:3b")
MAX_ITER = int(os.getenv("LAB_MAX_ITERACIONES", "12"))
TEMPERATURA = float(os.getenv("LAB_TEMPERATURA", "0"))
OBJETIVO = os.getenv("LAB_OBJETIVO", "victima")

TRAZAS_DIR = Path("/output/trazas")
METRICAS_DIR = Path("/output/metricas")

SYSTEM_PROMPT = f"""Eres un agente analista de un SOC (Security Operations Center).
Tu misión es revisar las alertas de red de un sensor IDS (Suricata) que vigila
el host {OBJETIVO}, determinar si hay un RECONOCIMIENTO en curso y documentarlo.

Trabajas en ciclos ReAct. En CADA turno respondes EXCLUSIVAMENTE con un objeto
JSON válido, sin texto adicional, con una de estas dos formas:

1) Para usar una herramienta:
{{"pensamiento": "<tu razonamiento breve>",
  "accion": {{"herramienta": "<nombre>", "args": {{...}}}}}}

2) Para terminar, cuando ya creaste el caso y el informe:
{{"pensamiento": "<cierre>",
  "final": {{"veredicto": "reconocimiento|benigno",
             "tecnicas": ["T1046", ...],
             "observables": ["ip=...","firma=..."],
             "resumen": "<2-3 frases>"}}}}

Herramientas disponibles:
{catalogo_para_prompt()}

Procedimiento OBLIGATORIO (en este orden, sin repetir herramientas):
1. Usa `consultar_alertas` UNA sola vez.
2. Para CADA firma distinta, toma su técnica del texto entre corchetes del
   mensaje y pásala SIN corchetes a `enriquecer_attack`
   (ejemplo correcto: {{"tecnica": "T1046"}}).
3. Usa `crear_caso` incluyendo TODAS las técnicas confirmadas.
4. Usa `generar_informe` con recomendaciones defensivas concretas (reglas IDS,
   rate limiting, reducción de superficie, ocultar banners).
5. Responde con `final` incluyendo esas mismas técnicas. NO vuelvas a llamar
   herramientas ya usadas ni inventes otras.
No inventes técnicas ni IPs: usa únicamente lo que devuelvan las herramientas."""


def ahora() -> str:
    return datetime.now(timezone.utc).isoformat()


def extraer_json(texto: str) -> dict | None:
    """Extrae el primer objeto JSON del texto (tolerante a ruido)."""
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


def main() -> int:
    TRAZAS_DIR.mkdir(parents=True, exist_ok=True)
    METRICAS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    traza_path = TRAZAS_DIR / f"traza-{ts}.jsonl"

    cliente = ollama.Client(host=OLLAMA_HOST)

    print("=" * 70)
    print(f"  Agente de detección — Lab 1 | modelo: {MODELO} @ {OLLAMA_HOST}")
    print(f"  Traza: {traza_path}")
    print("=" * 70)

    mensajes = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": "Analiza las alertas del sensor y documenta "
                                     "el incidente si corresponde."},
    ]

    herramientas_usadas: list[str] = []
    veredicto_final: dict = {}
    tecnicas_caso: list[str] = []
    inicio = time.time()
    t_inicio_iso = ahora()

    with traza_path.open("w", encoding="utf-8") as traza:
        def anotar(**campos):
            campos.setdefault("timestamp", ahora())
            traza.write(json.dumps(campos, ensure_ascii=False) + "\n")
            traza.flush()

        anotar(evento="inicio", modelo=MODELO, objetivo=OBJETIVO)

        for paso in range(1, MAX_ITER + 1):
            try:
                resp = cliente.chat(
                    model=MODELO,
                    messages=mensajes,
                    format="json",
                    options={"temperature": TEMPERATURA, "num_predict": 512,
                             "num_ctx": 4096},
                )
            except Exception as exc:  # noqa: BLE001
                print(f"\n[!] Error al consultar Ollama: {exc}")
                print("    Verifica OLLAMA_HOST y que el modelo esté descargado "
                      "(docker compose exec ollama ollama pull %s)." % MODELO)
                anotar(evento="error_llm", detalle=str(exc))
                return 1

            contenido = resp["message"]["content"]
            obj = extraer_json(contenido)
            if obj is None:
                print(f"\n[paso {paso}] Respuesta no parseable, reintentando...")
                anotar(evento="parse_error", paso=paso, bruto=contenido[:500])
                mensajes.append({"role": "assistant", "content": contenido})
                mensajes.append({"role": "user", "content": "Responde SOLO con el "
                                 "JSON indicado, sin texto adicional."})
                continue

            pensamiento = obj.get("pensamiento", "")
            print(f"\n[paso {paso}] 🧠 {pensamiento}")
            mensajes.append({"role": "assistant", "content": json.dumps(obj, ensure_ascii=False)})

            if "final" in obj or "respuesta_final" in obj:
                veredicto_final = obj.get("final") or obj.get("respuesta_final") or {}
                # Tolera el typo "verdicto" que a veces emite el modelo.
                ver = (veredicto_final.get("veredicto")
                       or veredicto_final.get("verdicto") or "")
                veredicto_final["veredicto"] = ver
                anotar(evento="final", paso=paso, pensamiento=pensamiento,
                       final=veredicto_final)
                # Red de seguridad: si el agente concluye incidente pero olvidó
                # crear caso/informe, se generan a partir de su veredicto.
                if ver == "reconocimiento":
                    if "crear_caso" not in herramientas_usadas:
                        HERRAMIENTAS["crear_caso"][0]({
                            "titulo": "Reconocimiento detectado",
                            "severidad": "media",
                            "tecnicas": veredicto_final.get("tecnicas", []),
                            "observables": veredicto_final.get("observables", []),
                            "resumen": veredicto_final.get("resumen", ""),
                        })
                    if "generar_informe" not in herramientas_usadas:
                        HERRAMIENTAS["generar_informe"][0]({
                            "titulo": "Reconocimiento detectado",
                            "veredicto": veredicto_final.get("veredicto", ""),
                            "tecnicas": veredicto_final.get("tecnicas", []),
                            "observables": veredicto_final.get("observables", []),
                            "recomendaciones": veredicto_final.get("recomendaciones", []),
                            "resumen": veredicto_final.get("resumen", ""),
                        })
                print(f"\n[✓] Veredicto: {veredicto_final.get('veredicto', 'n/d')}")
                break

            accion = obj.get("accion") or {}
            nombre = accion.get("herramienta", "")
            args = accion.get("args", {}) or {}
            if nombre not in HERRAMIENTAS:
                print(f"    ⚙️ herramienta desconocida: {nombre}")
                anotar(evento="herramienta_invalida", paso=paso, nombre=nombre)
                mensajes.append({"role": "user", "content": f"Herramienta '{nombre}' "
                                 "no existe. Usa una de la lista."})
                continue

            print(f"    ⚙️ {nombre}({json.dumps(args, ensure_ascii=False)})")
            funcion = HERRAMIENTAS[nombre][0]
            try:
                observacion = funcion(args)
            except Exception as exc:  # noqa: BLE001
                observacion = {"error": str(exc)}
            herramientas_usadas.append(nombre)
            if nombre == "crear_caso":
                tecnicas_caso = [t.strip().strip("[]").strip().upper()
                                 for t in (args.get("tecnicas") or [])] or tecnicas_caso
            print(f"    └─ {json.dumps(observacion, ensure_ascii=False)[:400]}")
            anotar(evento="accion", paso=paso, pensamiento=pensamiento,
                   herramienta=nombre, args=args, observacion=observacion)

            mensajes.append({"role": "user", "content": "Observación: "
                             + json.dumps(observacion, ensure_ascii=False)})

            # Cierre anticipado: con caso e informe ya generados, la tarea está
            # completa. Evita que el modelo siga iterando hasta el máximo.
            if {"crear_caso", "generar_informe"} <= set(herramientas_usadas):
                veredicto_final = {
                    "veredicto": "reconocimiento",
                    "tecnicas": sorted(set(tecnicas_caso)),
                    "observables": [],
                    "resumen": "Caso e informe generados a partir de las alertas "
                               "del sensor Suricata.",
                }
                anotar(evento="final_auto", paso=paso, final=veredicto_final)
                print(f"\n[✓] Veredicto (cierre automático): reconocimiento "
                      f"| técnicas={veredicto_final['tecnicas']}")
                break
        else:
            print("\n[!] Se alcanzó el máximo de iteraciones sin veredicto final.")
            anotar(evento="sin_final", max_iter=MAX_ITER)

        duracion = round(time.time() - inicio, 2)
        anotar(evento="fin", duracion_s=duracion, pasos=paso,
               herramientas_usadas=herramientas_usadas)

    # Métricas de la corrida.
    metricas = {
        "corrida": ts,
        "modelo": MODELO,
        "inicio": t_inicio_iso,
        "fin": ahora(),
        "duracion_s": duracion,
        "pasos": paso,
        "herramientas_usadas": herramientas_usadas,
        "num_llamadas_herramienta": len(herramientas_usadas),
        "veredicto": veredicto_final.get("veredicto", "n/d"),
        "tecnicas_detectadas": sorted(set(veredicto_final.get("tecnicas", []))
                                      | set(tecnicas_caso)),
    }
    ruta_metricas = METRICAS_DIR / f"run-{ts}.json"
    ruta_metricas.write_text(json.dumps(metricas, ensure_ascii=False, indent=2),
                             encoding="utf-8")
    print(f"\n[OK] Métricas de la corrida en {ruta_metricas}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
