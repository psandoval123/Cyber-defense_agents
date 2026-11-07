"""Agrega las métricas del Laboratorio 3 (hunting) desde output/metricas_hunt/.

Se ejecuta en el HOST, desde la carpeta del laboratorio:

    python3 scripts/calcular_metricas.py

Métricas (docs/05_evaluacion.md), sobre las corridas del agente:
  - Recall de caza: ¿encontró el beacon sembrado?
  - Falsos positivos: ¿marcó como amenaza algo benigno (NTP)?
  - Cobertura MITRE ATT&CK: técnicas correctas frente a las esperadas.
  - Profundidad de razonamiento: iteraciones del grafo.
  - Fundamentación (RAG): ¿citó el playbook?
  - Reproducibilidad: resultado estable en n corridas.
"""

from __future__ import annotations

import json
import statistics
from datetime import datetime
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
METRICAS_DIR = BASE / "output" / "metricas_hunt"


def main() -> int:
    corridas = sorted(METRICAS_DIR.glob("run-*.json")) if METRICAS_DIR.exists() else []
    print("=" * 70)
    print("  Métricas del Laboratorio 3 — threat hunting")
    print("=" * 70)

    if not corridas:
        print("\n[!] No hay corridas en output/metricas_hunt/. Ejecuta el agente.")
        return 1

    recalls, fps, coberturas, iteraciones, tiempos, rags = [], [], [], [], [], []
    filas = []
    for c in corridas:
        d = json.loads(c.read_text(encoding="utf-8"))
        recalls.append(d.get("recall_caza", 0))
        fps.append(d.get("falso_positivo", 0))
        coberturas.append(d.get("cobertura_attack", 0.0))
        iteraciones.append(d.get("iteraciones_grafo", 0))
        tiempos.append(d.get("duracion_s", 0.0))
        rags.append(1 if d.get("rag_citado") else 0)
        filas.append((d.get("corrida", "?"), d.get("recall_caza", 0),
                      d.get("falso_positivo", 0), d.get("cobertura_attack", 0.0),
                      d.get("iteraciones_grafo", 0), d.get("duracion_s", 0.0),
                      d.get("c2_detectado", "-")))

    n = len(corridas)
    print(f"\nCorridas: {n}\n")
    print(f"  {'corrida':20} {'recall':>6} {'FP':>3} {'cobATT':>7} {'iter':>5} {'seg':>7}  C2")
    for f in filas:
        print("  {:20} {:>6} {:>3} {:>7} {:>5} {:>7}  {}".format(*f))

    tasa_recall = statistics.mean(recalls)
    reproducibilidad = sum(1 for r in recalls if r == 1) / n
    print("\nResumen:")
    print(f"  Recall de caza (tasa): {tasa_recall:.0%}")
    print(f"  Falsos positivos (total): {sum(fps)}")
    print(f"  Cobertura ATT&CK (prom.): {statistics.mean(coberturas):.2f}")
    print(f"  Iteraciones del grafo (prom.): {statistics.mean(iteraciones):.1f}")
    print(f"  Tiempo de caza (prom.): {statistics.mean(tiempos):.1f} s")
    print(f"  Fundamentación RAG (tasa): {statistics.mean(rags):.0%}")
    print(f"  Reproducibilidad (recall estable): {reproducibilidad:.0%}")

    resumen = {
        "generado": datetime.utcnow().isoformat() + "Z",
        "n_corridas": n,
        "recall_caza": round(tasa_recall, 2),
        "falsos_positivos_total": sum(fps),
        "cobertura_attack_prom": round(statistics.mean(coberturas), 2),
        "iteraciones_prom": round(statistics.mean(iteraciones), 1),
        "tiempo_prom_s": round(statistics.mean(tiempos), 1),
        "rag_citado_tasa": round(statistics.mean(rags), 2),
        "reproducibilidad": round(reproducibilidad, 2),
    }
    (METRICAS_DIR / "resumen.json").write_text(
        json.dumps(resumen, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[OK] Resumen en {METRICAS_DIR / 'resumen.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
