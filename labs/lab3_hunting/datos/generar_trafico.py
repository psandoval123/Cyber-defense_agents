"""Generador de tráfico sintético para el Laboratorio 3 (threat hunting).

Produce logs de red en formato estilo Zeek (JSON Lines) de forma DETERMINISTA
(semilla fija), para cazar un C2 *beaconing* oculto entre tráfico normal:

  output/logs/conn.log   conexiones (JSONL estilo Zeek conn.log)
  output/logs/dns.log    consultas DNS (JSONL estilo Zeek dns.log)
  output/ground_truth.json   qué pares son beacon / benigno-periódico / ruido

Escenario (ventana de 1 hora):
  - Ruido: navegación web a muchos destinos, intervalos irregulares (Poisson).
  - Legítimo periódico: NTP cada ~1024 s (periódico PERO benigno).
  - Beacon oculto: un host interno -> un C2 externo cada ~60 s con jitter pequeño
    (muchas conexiones, varianza muy baja). Ninguna firma IDS lo detecta;
    solo el patrón temporal lo delata.

No usa librerías externas (solo la estándar). No hay datos reales ni ataques
reales: todo es sintético y las IPs externas usan rangos de documentación
(192.0.2.0/24, TEST-NET-1).
"""

from __future__ import annotations

import json
import random
import uuid
from datetime import datetime, timezone
from pathlib import Path

# --- Parámetros reproducibles ---
SEMILLA = 20261107
INICIO = datetime(2026, 11, 7, 9, 0, 0, tzinfo=timezone.utc).timestamp()
VENTANA_S = 3600  # 1 hora

BASE = Path(__file__).resolve().parent.parent
LOGS_DIR = BASE / "output" / "logs"
GROUND_TRUTH = BASE / "output" / "ground_truth.json"

# Red interna y hosts (workstations).
HOSTS_INTERNOS = [f"10.10.10.{i}" for i in range(11, 21)]

# Destinos web "normales" (rango de documentación TEST-NET-1).
WEB_DESTINOS = [f"192.0.2.{i}" for i in range(10, 60)]
WEB_DOMINIOS = [
    "cdn.example.com", "api.example.net", "static.example.org",
    "news.example.com", "mail.example.net", "search.example.org",
    "updates.example.com", "images.example.net",
]

# Beacon oculto (la amenaza a cazar).
BEACON_SRC = "10.10.10.17"
BEACON_C2_IP = "192.0.2.66"
BEACON_C2_DOMINIO = "cdn-sync-telemetry.net"
BEACON_INTERVALO_S = 60
BEACON_JITTER_S = 3          # varianza pequeña -> CV bajo
BEACON_PUERTO = 443

# Tráfico legítimo periódico (NTP): periódico PERO benigno.
NTP_SRCS = ["10.10.10.11", "10.10.10.12"]
NTP_DST = "200.16.0.2"
NTP_INTERVALO_S = 300        # periódico y con CV bajo, pero BENIGNO (señuelo)
NTP_PUERTO = 123


def nuevo_uid(rnd: random.Random) -> str:
    return "C" + uuid.UUID(int=rnd.getrandbits(128)).hex[:16]


def conn(ts, src, dst, puerto, proto, service, orig_b, resp_b, rnd) -> dict:
    return {
        "ts": round(ts, 6),
        "uid": nuevo_uid(rnd),
        "orig_h": src,
        "resp_h": dst,
        "resp_p": puerto,
        "proto": proto,
        "service": service,
        "duration": round(rnd.uniform(0.05, 2.5), 4),
        "orig_bytes": orig_b,
        "resp_bytes": resp_b,
    }


def dns(ts, src, query, qtype="A", answer="192.0.2.66") -> dict:
    return {"ts": round(ts, 6), "orig_h": src, "query": query,
            "qtype": qtype, "answer": answer}


def generar():
    rnd = random.Random(SEMILLA)
    conns: list[dict] = []
    dnss: list[dict] = []

    # --- 1. Ruido: navegación web irregular (proceso de Poisson por host) ---
    for host in HOSTS_INTERNOS:
        t = INICIO + rnd.uniform(0, 30)
        while t < INICIO + VENTANA_S:
            dst = rnd.choice(WEB_DESTINOS)
            dom = rnd.choice(WEB_DOMINIOS)
            conns.append(conn(t, host, dst, rnd.choice([80, 443]), "tcp", "http",
                              rnd.randint(200, 1500), rnd.randint(500, 60000), rnd))
            if rnd.random() < 0.7:
                dnss.append(dns(t - rnd.uniform(0.01, 0.2), host, dom, "A",
                                rnd.choice(WEB_DESTINOS)))
            # Intervalos irregulares: media ~45 s, muy variable (CV alto).
            t += rnd.expovariate(1 / 45.0)

    # --- 2. Legítimo periódico: NTP cada ~1024 s (benigno) ---
    for host in NTP_SRCS:
        t = INICIO + rnd.uniform(0, 50)
        while t < INICIO + VENTANA_S:
            conns.append(conn(t, host, NTP_DST, NTP_PUERTO, "udp", "ntp",
                              76, 76, rnd))
            t += NTP_INTERVALO_S + rnd.uniform(-2, 2)

    # --- 3. Beacon oculto: cada ~60 s con jitter pequeño (la amenaza) ---
    t = INICIO + rnd.uniform(0, BEACON_INTERVALO_S)
    beacon_n = 0
    while t < INICIO + VENTANA_S:
        conns.append(conn(t, BEACON_SRC, BEACON_C2_IP, BEACON_PUERTO, "tcp", "ssl",
                          rnd.randint(120, 180), rnd.randint(200, 350), rnd))
        # Resolución DNS periódica del dominio C2.
        if beacon_n % 5 == 0:
            dnss.append(dns(t - rnd.uniform(0.01, 0.1), BEACON_SRC,
                            BEACON_C2_DOMINIO, "A", BEACON_C2_IP))
        beacon_n += 1
        t += BEACON_INTERVALO_S + rnd.uniform(-BEACON_JITTER_S, BEACON_JITTER_S)

    # Orden cronológico (como un log real).
    conns.sort(key=lambda e: e["ts"])
    dnss.sort(key=lambda e: e["ts"])

    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    with (LOGS_DIR / "conn.log").open("w", encoding="utf-8") as f:
        for e in conns:
            f.write(json.dumps(e) + "\n")
    with (LOGS_DIR / "dns.log").open("w", encoding="utf-8") as f:
        for e in dnss:
            f.write(json.dumps(e) + "\n")

    ground = {
        "generado": datetime.now(timezone.utc).isoformat(),
        "semilla": SEMILLA,
        "ventana_s": VENTANA_S,
        "amenaza": {
            "tipo": "C2 beaconing",
            "src": BEACON_SRC,
            "dst": BEACON_C2_IP,
            "dominio": BEACON_C2_DOMINIO,
            "intervalo_s": BEACON_INTERVALO_S,
            "conexiones": beacon_n,
            "attack": ["T1071.001", "T1571"],
        },
        "benigno_periodico": [
            {"src": s, "dst": NTP_DST, "service": "ntp",
             "intervalo_s": NTP_INTERVALO_S, "nota": "periódico pero legítimo"}
            for s in NTP_SRCS
        ],
        "ruido": "navegación web irregular a múltiples destinos (no es amenaza)",
    }
    GROUND_TRUTH.write_text(json.dumps(ground, ensure_ascii=False, indent=2),
                            encoding="utf-8")

    # Resumen por pantalla.
    print(f"[OK] conn.log: {len(conns)} conexiones  |  dns.log: {len(dnss)} consultas")
    print(f"[OK] Beacon sembrado: {BEACON_SRC} -> {BEACON_C2_IP} "
          f"({beacon_n} latidos cada ~{BEACON_INTERVALO_S}s)")
    print(f"[OK] Ground truth: {GROUND_TRUTH}")
    return conns, dnss, ground


if __name__ == "__main__":
    generar()
