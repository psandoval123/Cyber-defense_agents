"""Adversario emulado del Laboratorio 1 (lado rojo, solo para ser DETECTADO).

Ejecuta un guion de reconocimiento DETERMINISTA y documentado contra la víctima
del laboratorio, dentro de una red Docker aislada. No explota nada: todas las
técnicas son de solo lectura (descubrimiento y enumeración). Su propósito es
producir telemetría realista para que el sensor Suricata y el agente de
detección la observen y clasifiquen.

Cada técnica se registra con marcas de tiempo en output/atacante/recon-<ts>.jsonl
para poder calcular después el MTTD (tiempo hasta la detección) y la cobertura
MITRE ATT&CK esperada.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

OUTPUT_DIR = Path("/output/atacante")

# Objetivo y lista blanca (defensa en profundidad: el adversario emulado NUNCA
# puede apuntar fuera de la víctima del laboratorio).
OBJETIVO = os.getenv("LAB_OBJETIVO", "172.28.0.10")
PERMITIDOS = {
    ip.strip()
    for ip in os.getenv("LAB_OBJETIVOS_PERMITIDOS", "172.28.0.10").split(",")
    if ip.strip()
}

# Guion de reconocimiento: (técnica ATT&CK, descripción, comando).
# El orden imita a un operador real: primero mapear puertos/servicios, luego
# tecnologías web y, por último, enumerar rutas.
GUION = [
    (
        "T1046",
        "Escaneo de puertos y versiones (nmap -sS -sV)",
        ["nmap", "-sS", "-sV", "-T4", "-p-", "--max-retries", "1", OBJETIVO],
    ),
    (
        "T1592.002",
        "Fingerprinting de tecnologias web (whatweb)",
        ["whatweb", "-a", "3", f"http://{OBJETIVO}"],
    ),
    (
        "T1595.003",
        "Enumeracion de rutas web (gobuster)",
        [
            "gobuster", "dir", "-q", "-t", "20",
            "-u", f"http://{OBJETIVO}",
            "-w", "/usr/share/dirb/wordlists/common.txt",
        ],
    ),
]


def ahora() -> str:
    return datetime.now(timezone.utc).isoformat()


def registrar(log, **campos) -> None:
    """Añade una línea JSON al log de la corrida y la muestra por pantalla."""
    campos.setdefault("timestamp", ahora())
    linea = json.dumps(campos, ensure_ascii=False, sort_keys=True)
    log.write(linea + "\n")
    log.flush()


def ejecutar_tecnica(log, tecnica: str, descripcion: str, comando: list[str]) -> None:
    print(f"\n[>] {tecnica} — {descripcion}")
    print(f"    $ {' '.join(comando)}")
    inicio = ahora()
    registrar(log, evento="inicio_tecnica", tecnica=tecnica,
              descripcion=descripcion, comando=comando, timestamp=inicio)
    try:
        proc = subprocess.run(comando, capture_output=True, text=True, timeout=600)
        salida = (proc.stdout or "") + (proc.stderr or "")
        codigo = proc.returncode
    except subprocess.TimeoutExpired:
        salida, codigo = "TIMEOUT", 124
    print(salida.strip()[:2000])
    registrar(log, evento="fin_tecnica", tecnica=tecnica, codigo=codigo,
              lineas_salida=len(salida.splitlines()), timestamp=ahora())


def main() -> int:
    if OBJETIVO not in PERMITIDOS:
        print(f"[!] Objetivo {OBJETIVO} fuera de la lista blanca {PERMITIDOS}. Abortando.",
              file=sys.stderr)
        return 2

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    ruta_log = OUTPUT_DIR / f"recon-{ts}.jsonl"

    print("=" * 70)
    print(f"  Adversario emulado — Lab 1 | objetivo: {OBJETIVO}")
    print(f"  Guion (solo lectura): {', '.join(t for t, _, _ in GUION)}")
    print(f"  Log: {ruta_log}")
    print("=" * 70)

    with ruta_log.open("w", encoding="utf-8") as log:
        registrar(log, evento="inicio_corrida", objetivo=OBJETIVO,
                  tecnicas_planeadas=[t for t, _, _ in GUION])
        for tecnica, descripcion, comando in GUION:
            ejecutar_tecnica(log, tecnica, descripcion, comando)
        registrar(log, evento="fin_corrida", objetivo=OBJETIVO)

    print(f"\n[OK] Reconocimiento completado. Timeline en {ruta_log}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
