"""Agrega las métricas del Laboratorio 2 (respuesta) desde output/.

Se ejecuta en el HOST, desde la carpeta del laboratorio:

    python3 scripts/calcular_metricas.py

Métricas (docs/05_evaluacion.md):
  - MTTR: tiempo medio desde la detección (1ª alerta) hasta la contención efectiva.
  - Tasa de contención: % de corridas donde el bloqueo quedó verificado.
  - Falsos positivos de respuesta: bloqueos a una IP distinta de la atacante.
  - Aprobación: reparto auto/manual/denegada (human-in-the-loop).
  - Reversibilidad: si se probó el rollback (órdenes 'unblock' aplicadas).
  - Automatización y reproducibilidad.
"""

from __future__ import annotations

import json
import statistics
from collections import Counter
from datetime import datetime
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
OUTPUT = BASE / "output"
EVE = OUTPUT / "suricata" / "eve.json"
METRICAS_DIR = OUTPUT / "metricas"
ORDENES_DIR = OUTPUT / "ordenes"


def ip_atacante_ground_truth() -> str | None:
    """La IP atacante real = la de origen con más alertas en el sensor."""
    if not EVE.exists():
        return None
    c: Counter[str] = Counter()
    for linea in EVE.read_text(encoding="utf-8", errors="ignore").splitlines():
        linea = linea.strip()
        if not linea:
            continue
        try:
            ev = json.loads(linea)
        except json.JSONDecodeError:
            continue
        if ev.get("event_type") == "alert" and ev.get("src_ip"):
            c[ev["src_ip"]] += 1
    return c.most_common(1)[0][0] if c else None


def rollback_probado() -> bool:
    if not ORDENES_DIR.exists():
        return False
    for f in ORDENES_DIR.glob("*.json"):
        try:
            o = json.loads(f.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if o.get("accion") == "unblock" and o.get("estado") == "aplicada":
            return True
    return False


def main() -> int:
    corridas = sorted(METRICAS_DIR.glob("run-*.json")) if METRICAS_DIR.exists() else []
    print("=" * 70)
    print("  Métricas del Laboratorio 2 — respuesta/contención")
    print("=" * 70)

    if not corridas:
        print("\n[!] No hay corridas en output/metricas/. Ejecuta el agente primero.")
        return 1

    atacante_real = ip_atacante_ground_truth()
    mttrs, contenidas, fps, aprob = [], 0, 0, Counter()
    filas = []
    for c in corridas:
        d = json.loads(c.read_text(encoding="utf-8"))
        ok = bool(d.get("contencion_ok"))
        contenidas += 1 if ok else 0
        if d.get("mttr_s") is not None:
            mttrs.append(d["mttr_s"])
        aprob[d.get("aprobacion", "n/a")] += 1
        ip_bloq = d.get("ip_bloqueada")
        # Falso positivo de respuesta: se bloqueó una IP que no es la atacante.
        if ip_bloq and atacante_real and ip_bloq != atacante_real:
            fps += 1
        filas.append((d.get("corrida", "?"), d.get("aprobacion", "?"),
                      ip_bloq or "-", "sí" if ok else "no",
                      d.get("mttr_s", "n/d"), d.get("duracion_s", "?")))

    n = len(corridas)
    print(f"\nCorridas: {n}  |  IP atacante (ground truth): {atacante_real}")
    print(f"\n  {'corrida':20} {'aprobacion':12} {'ip_bloqueada':16} {'conten.':8} {'mttr_s':>8} {'seg':>8}")
    for f in filas:
        print("  {:20} {:12} {:16} {:8} {:>8} {:>8}".format(*f))

    tasa_contencion = contenidas / n
    reproducibilidad = contenidas / n  # resultado estable = contención lograda
    print("\nResumen:")
    print(f"  MTTR promedio: {round(statistics.mean(mttrs), 2) if mttrs else 'n/d'} s")
    print(f"  Tasa de contención: {tasa_contencion:.0%} ({contenidas}/{n})")
    print(f"  Falsos positivos de respuesta: {fps}")
    print(f"  Aprobación (reparto): {dict(aprob)}")
    print(f"  Reversibilidad (rollback probado): {'sí' if rollback_probado() else 'no'}")
    print(f"  Automatización: 100% (el agente ejecuta todo el flujo; el bloqueo "
          f"requiere 1 aprobación)")
    print(f"  Reproducibilidad: {reproducibilidad:.0%}")

    resumen = {
        "generado": datetime.utcnow().isoformat() + "Z",
        "n_corridas": n,
        "ip_atacante_ground_truth": atacante_real,
        "mttr_prom_s": round(statistics.mean(mttrs), 2) if mttrs else None,
        "tasa_contencion": round(tasa_contencion, 2),
        "falsos_positivos_respuesta": fps,
        "aprobacion": dict(aprob),
        "rollback_probado": rollback_probado(),
        "reproducibilidad": round(reproducibilidad, 2),
    }
    METRICAS_DIR.mkdir(parents=True, exist_ok=True)
    (METRICAS_DIR / "resumen.json").write_text(
        json.dumps(resumen, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[OK] Resumen en {METRICAS_DIR / 'resumen.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
