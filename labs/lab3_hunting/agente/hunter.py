"""Ejecuta una cacería del Laboratorio 3 por línea de comandos.

Corre el grafo LangGraph sobre los logs sintéticos y produce evidencia:
  output/trazas_hunt/traza-<ts>.jsonl        pasos del grafo (trazabilidad)
  output/informes_hunt/informe-<ts>.md       informe de caza
  output/metricas_hunt/run-<ts>.json         métricas de la corrida

Las métricas se comparan contra output/ground_truth.json (sin trampas).
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

from grafo import construir_grafo

BASE = Path(__file__).resolve().parent.parent
OUT = BASE / "output"
GROUND = OUT / "ground_truth.json"
TRAZAS = OUT / "trazas_hunt"
INFORMES = OUT / "informes_hunt"
METRICAS = OUT / "metricas_hunt"


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def escribir_informe(ver: dict, iteraciones: int, ts: str) -> Path:
    INFORMES.mkdir(parents=True, exist_ok=True)
    tecnicas = ver.get("tecnicas", [])
    lineas = [
        f"# Informe de caza — {ts}",
        "",
        f"- **Amenaza encontrada:** {ver.get('amenaza_encontrada')}",
        f"- **Host comprometido (origen):** {ver.get('host_comprometido', 'n/d')}",
        f"- **C2 (destino):** {ver.get('c2_ip', 'n/d')}",
        f"- **Dominio C2:** {ver.get('c2_dominio', 'n/d')}",
        f"- **Iteraciones del grafo:** {iteraciones}",
        f"- **Playbook citado (RAG):** {ver.get('playbook', 'n/d')}",
        f"- **Generado por:** agente de hunting (Lab 3, LangGraph + RAG, LLM local)",
        "",
        "## Resumen",
        "",
        ver.get("resumen", "(sin resumen)"),
        "",
        "## Técnicas MITRE ATT&CK",
        "",
    ]
    lineas += [f"- `{t}`" for t in tecnicas] or ["- (ninguna)"]
    lineas += ["", "## Descartados como benignos", ""]
    lineas += [f"- {b}" for b in ver.get("benignos_descartados", [])] or ["- (ninguno)"]
    lineas += [""]
    ruta = INFORMES / f"informe-{ts}.md"
    ruta.write_text("\n".join(lineas), encoding="utf-8")
    return ruta


def main() -> int:
    ts = _ts()
    print("=" * 70)
    print("  Agente de hunting — Lab 3 | grafo LangGraph + RAG + LLM local")
    print("=" * 70)

    grafo = construir_grafo()
    inicio = time.time()
    estado_final = grafo.invoke({"traza": []})
    duracion = round(time.time() - inicio, 2)

    ver = estado_final.get("veredicto", {})
    iteraciones = estado_final.get("iteraciones", 0)
    traza = estado_final.get("traza", [])

    # Evidencia.
    TRAZAS.mkdir(parents=True, exist_ok=True)
    with (TRAZAS / f"traza-{ts}.jsonl").open("w", encoding="utf-8") as f:
        for paso in traza:
            f.write(json.dumps(paso, ensure_ascii=False) + "\n")
    ruta_informe = escribir_informe(ver, iteraciones, ts)

    # Métricas contra el ground truth.
    ground = json.loads(GROUND.read_text(encoding="utf-8"))
    beacon = ground["amenaza"]
    b_src, b_dst, b_dom = beacon["src"], beacon["dst"], beacon["dominio"]
    b_tecnicas = set(beacon.get("attack", []))
    benignos_dst = {b["dst"] for b in ground.get("benigno_periodico", [])}
    benignos_src = {b["src"] for b in ground.get("benigno_periodico", [])}

    encontrada = bool(ver.get("amenaza_encontrada"))
    host = ver.get("host_comprometido", "")
    c2_ip = ver.get("c2_ip", "")
    c2_dom = ver.get("c2_dominio", "")
    # Acierta si identifica el beacon por su dominio, su C2 o el host comprometido.
    amenaza_correcta = encontrada and (c2_dom == b_dom or c2_ip == b_dst or host == b_src)
    # Falso positivo: señala como C2 un destino/host benigno (p. ej. NTP).
    falso_positivo = encontrada and (c2_ip in benignos_dst or host in benignos_src)

    detectadas = set(ver.get("tecnicas", []))
    cobertura = round(len(detectadas & b_tecnicas) / len(b_tecnicas), 2) if b_tecnicas else 0.0

    metricas = {
        "corrida": ts,
        "duracion_s": duracion,
        "iteraciones_grafo": iteraciones,
        "amenaza_encontrada": encontrada,
        "host_detectado": host,
        "c2_detectado": c2_ip,
        "dominio_detectado": c2_dom,
        "beacon_esperado": {"host": b_src, "c2": b_dst, "dominio": b_dom},
        "recall_caza": 1 if amenaza_correcta else 0,
        "falso_positivo": 1 if falso_positivo else 0,
        "tecnicas_detectadas": sorted(detectadas),
        "cobertura_attack": cobertura,
        "rag_citado": bool(ver.get("playbook")),
        "playbook": ver.get("playbook"),
    }
    METRICAS.mkdir(parents=True, exist_ok=True)
    (METRICAS / f"run-{ts}.json").write_text(
        json.dumps(metricas, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"\n[resultado] amenaza correcta: {amenaza_correcta} | "
          f"falso positivo: {falso_positivo} | iteraciones: {iteraciones} | "
          f"{duracion}s")
    print(f"[OK] Informe: {ruta_informe}")
    print(f"[OK] Métricas: {METRICAS / f'run-{ts}.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
