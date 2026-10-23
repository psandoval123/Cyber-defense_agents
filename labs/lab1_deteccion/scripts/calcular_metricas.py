"""Agrega las métricas del Laboratorio 1 a partir de las evidencias en output/.

Se ejecuta en el HOST (no en Docker), desde la carpeta del laboratorio:

    python3 scripts/calcular_metricas.py

Calcula, sobre las corridas registradas, las métricas obligatorias de
docs/05_evaluacion.md:
  - MTTD: tiempo desde el inicio del reconocimiento hasta la primera alerta.
  - Precisión / Recall / F1: técnicas detectadas por el agente frente a las
    realmente ejecutadas por el adversario emulado (ground truth).
  - Cobertura MITRE ATT&CK.
  - Nivel de automatización y reproducibilidad.

No inventa datos: si no hay evidencias, lo indica y no reporta métricas.
"""

from __future__ import annotations

import json
import statistics
from datetime import datetime
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
OUTPUT = BASE / "output"
EVE = OUTPUT / "suricata" / "eve.json"
ATACANTE_DIR = OUTPUT / "atacante"
METRICAS_DIR = OUTPUT / "metricas"

# Ground truth: técnicas que el adversario emulado ejecuta en su guion.
TECNICAS_ESPERADAS = {"T1046", "T1592.002", "T1595.003"}


def parse_ts(valor: str) -> datetime | None:
    if not valor:
        return None
    valor = valor.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(valor)
    except ValueError:
        return None


def cargar_alertas() -> list[dict]:
    if not EVE.exists():
        return []
    alertas = []
    for linea in EVE.read_text(encoding="utf-8", errors="ignore").splitlines():
        linea = linea.strip()
        if not linea:
            continue
        try:
            ev = json.loads(linea)
        except json.JSONDecodeError:
            continue
        if ev.get("event_type") == "alert":
            alertas.append(ev)
    return alertas


def inicio_ataque() -> datetime | None:
    """Primera marca 'inicio_corrida' entre los timelines del atacante."""
    if not ATACANTE_DIR.exists():
        return None
    marcas = []
    for f in ATACANTE_DIR.glob("recon-*.jsonl"):
        for linea in f.read_text(encoding="utf-8", errors="ignore").splitlines():
            try:
                ev = json.loads(linea)
            except json.JSONDecodeError:
                continue
            if ev.get("evento") == "inicio_corrida":
                ts = parse_ts(ev.get("timestamp", ""))
                if ts:
                    marcas.append(ts)
    return min(marcas) if marcas else None


def f1(precision: float, recall: float) -> float:
    return 0.0 if (precision + recall) == 0 else 2 * precision * recall / (precision + recall)


def main() -> int:
    alertas = cargar_alertas()
    corridas = sorted(METRICAS_DIR.glob("run-*.json")) if METRICAS_DIR.exists() else []

    print("=" * 70)
    print("  Métricas del Laboratorio 1 — detección de reconocimiento")
    print("=" * 70)

    if not alertas and not corridas:
        print("\n[!] No hay evidencias en output/. Ejecuta primero el atacante y el agente.")
        return 1

    # --- MTTD ---
    t0 = inicio_ataque()
    mttd_s = None
    if t0 and alertas:
        ts_alertas = sorted(t for t in (parse_ts(a.get("timestamp", "")) for a in alertas) if t)
        primera = next((t for t in ts_alertas if t >= t0), ts_alertas[0] if ts_alertas else None)
        if primera:
            mttd_s = round((primera - t0).total_seconds(), 2)

    # --- Técnicas realmente alertadas por el sensor ---
    import re
    rx = re.compile(r"\[(T\d{4}(?:\.\d{3})?)\]")
    tecnicas_sensor = set()
    for a in alertas:
        m = rx.search(a.get("alert", {}).get("signature", ""))
        if m:
            tecnicas_sensor.add(m.group(1))

    # --- Precisión / Recall / F1 por corrida del agente ---
    filas = []
    precisiones, recalls, f1s, automatizaciones = [], [], [], []
    veredictos = []
    for c in corridas:
        d = json.loads(c.read_text(encoding="utf-8"))
        detectadas = set(d.get("tecnicas_detectadas", []))
        tp = len(detectadas & TECNICAS_ESPERADAS)
        prec = tp / len(detectadas) if detectadas else 0.0
        rec = tp / len(TECNICAS_ESPERADAS) if TECNICAS_ESPERADAS else 0.0
        _f1 = f1(prec, rec)
        # Automatización: toda la corrida la ejecuta el agente sin intervención.
        auto = 1.0 if d.get("num_llamadas_herramienta", 0) > 0 else 0.0
        precisiones.append(prec); recalls.append(rec); f1s.append(_f1)
        automatizaciones.append(auto); veredictos.append(d.get("veredicto", "n/d"))
        filas.append((d.get("corrida", "?"), d.get("veredicto", "n/d"),
                      round(prec, 2), round(rec, 2), round(_f1, 2),
                      d.get("pasos", "?"), d.get("duracion_s", "?")))

    cobertura = (len(tecnicas_sensor & TECNICAS_ESPERADAS) / len(TECNICAS_ESPERADAS)
                 if TECNICAS_ESPERADAS else 0.0)
    reproducibilidad = (veredictos.count("reconocimiento") / len(veredictos)
                        if veredictos else 0.0)

    print(f"\nAlertas del sensor: {len(alertas)}  |  corridas del agente: {len(corridas)}")
    print(f"Técnicas esperadas (ground truth): {sorted(TECNICAS_ESPERADAS)}")
    print(f"Técnicas alertadas por el sensor:  {sorted(tecnicas_sensor)}")
    print(f"\nMTTD (inicio ataque -> primera alerta): "
          f"{mttd_s if mttd_s is not None else 'n/d'} s")
    print(f"Cobertura MITRE ATT&CK (sensor): {cobertura:.0%}")

    if filas:
        print("\nPor corrida (agente):")
        print(f"  {'corrida':20} {'veredicto':16} {'prec':>5} {'rec':>5} {'f1':>5} {'pasos':>6} {'seg':>7}")
        for fila in filas:
            print("  {:20} {:16} {:>5} {:>5} {:>5} {:>6} {:>7}".format(*fila))
        print("\nPromedios:")
        print(f"  Precisión: {statistics.mean(precisiones):.2f}")
        print(f"  Recall:    {statistics.mean(recalls):.2f}")
        print(f"  F1:        {statistics.mean(f1s):.2f}")
        print(f"  Automatización: {statistics.mean(automatizaciones):.0%}")
    print(f"  Reproducibilidad (veredicto 'reconocimiento'): {reproducibilidad:.0%}")

    resumen = {
        "generado": datetime.utcnow().isoformat() + "Z",
        "n_alertas": len(alertas),
        "n_corridas": len(corridas),
        "tecnicas_esperadas": sorted(TECNICAS_ESPERADAS),
        "tecnicas_sensor": sorted(tecnicas_sensor),
        "mttd_s": mttd_s,
        "cobertura_attack": round(cobertura, 2),
        "precision_prom": round(statistics.mean(precisiones), 2) if precisiones else None,
        "recall_prom": round(statistics.mean(recalls), 2) if recalls else None,
        "f1_prom": round(statistics.mean(f1s), 2) if f1s else None,
        "automatizacion_prom": round(statistics.mean(automatizaciones), 2) if automatizaciones else None,
        "reproducibilidad": round(reproducibilidad, 2),
    }
    METRICAS_DIR.mkdir(parents=True, exist_ok=True)
    (METRICAS_DIR / "resumen.json").write_text(
        json.dumps(resumen, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[OK] Resumen agregado en {METRICAS_DIR / 'resumen.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
