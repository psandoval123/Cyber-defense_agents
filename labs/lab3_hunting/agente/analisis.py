"""Motor de análisis de beaconing para el Laboratorio 3 (determinista).

Convierte los logs de conexión (estilo Zeek) en CANDIDATOS a beaconing,
rankeados por regularidad temporal. NO decide si algo es malicioso: solo mide
y expone features; la clasificación benigno/amenaza la hace el agente (LLM+RAG),
que debe razonar (p. ej. NTP en puerto 123 es periódico PERO legítimo).

Función de un beacon: conexiones a intervalos muy regulares → bajo
**coeficiente de variación** (CV = desviación / media de los intervalos).

Solo usa la librería estándar. Se expone como herramienta del agente.
"""

from __future__ import annotations

import ipaddress
import json
import math
import statistics
from collections import defaultdict
from pathlib import Path

# Umbrales (ajustables; documentados para la tesis).
MIN_EVENTOS = 8        # nº mínimo de conexiones para evaluar periodicidad
CV_CANDIDATO = 0.25    # CV por debajo del cual el par se marca como periódico


def cargar_conn(path: str | Path) -> list[dict]:
    eventos = []
    for linea in Path(path).read_text(encoding="utf-8").splitlines():
        linea = linea.strip()
        if linea:
            try:
                eventos.append(json.loads(linea))
            except json.JSONDecodeError:
                continue
    return eventos


# Redes internas de la organización (RFC1918). "Externo" = fuera de estas.
# No usamos ip_address.is_private porque marca como privados los rangos de
# documentación (p. ej. 192.0.2.0/24) que aquí representan destinos externos.
_REDES_INTERNAS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def es_externo(ip: str) -> bool:
    """True si la IP está fuera de la red interna de la organización."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not any(addr in red for red in _REDES_INTERNAS)


def _metricas_intervalos(timestamps: list[float]) -> dict:
    ts = sorted(timestamps)
    deltas = [b - a for a, b in zip(ts, ts[1:])]
    media = statistics.mean(deltas)
    desv = statistics.pstdev(deltas) if len(deltas) > 1 else 0.0
    cv = (desv / media) if media else 0.0
    return {
        "intervalo_medio_s": round(media, 2),
        "jitter_s": round(desv, 2),
        "cv": round(cv, 4),
        "span_min": round((ts[-1] - ts[0]) / 60, 1),
    }


def analizar_beaconing(conns: list[dict], min_eventos: int = MIN_EVENTOS,
                       cv_candidato: float = CV_CANDIDATO) -> list[dict]:
    """Agrupa por par (origen, destino) y puntúa su regularidad temporal.

    Devuelve los candidatos ordenados por `puntuacion` descendente. La
    puntuación premia regularidad (CV bajo) y persistencia (muchas conexiones).
    """
    pares: dict[tuple, list[dict]] = defaultdict(list)
    for e in conns:
        pares[(e.get("orig_h"), e.get("resp_h"))].append(e)

    candidatos = []
    for (src, dst), eventos in pares.items():
        if len(eventos) < min_eventos:
            continue
        ts = [e["ts"] for e in eventos]
        m = _metricas_intervalos(ts)
        cv = m["cv"]
        # Regularidad en [0,1] y persistencia saturada a 1 en ~20 conexiones.
        regularidad = 1.0 / (1.0 + cv)
        persistencia = min(1.0, len(eventos) / 20.0)
        puntuacion = round(regularidad * persistencia, 3)

        servicios = {e.get("service") for e in eventos}
        puertos = {e.get("resp_p") for e in eventos}
        orig_bytes = [e.get("orig_bytes", 0) for e in eventos]
        resp_bytes = [e.get("resp_bytes", 0) for e in eventos]

        candidatos.append({
            "src": src,
            "dst": dst,
            "dst_externo": es_externo(dst),
            "service": sorted(s for s in servicios if s),
            "resp_p": sorted(p for p in puertos if p is not None),
            "conexiones": len(eventos),
            **m,
            "orig_bytes_prom": round(statistics.mean(orig_bytes), 1),
            "resp_bytes_prom": round(statistics.mean(resp_bytes), 1),
            "periodico": cv < cv_candidato,
            "puntuacion": puntuacion,
        })

    candidatos.sort(key=lambda c: c["puntuacion"], reverse=True)
    return candidatos


def serie_temporal(conns: list[dict], src: str, dst: str) -> list[float]:
    """Timestamps ordenados de un par (para graficar los 'latidos')."""
    ts = [e["ts"] for e in conns if e.get("orig_h") == src and e.get("resp_h") == dst]
    return sorted(ts)


def cargar_dns(path: str | Path) -> list[dict]:
    registros = []
    for linea in Path(path).read_text(encoding="utf-8").splitlines():
        linea = linea.strip()
        if linea:
            try:
                registros.append(json.loads(linea))
            except json.JSONDecodeError:
                continue
    return registros


def dominios_de_ip(dnss: list[dict], ip: str) -> list[str]:
    """Dominios que resolvieron a una IP (según el campo answer del dns.log)."""
    return sorted({d.get("query") for d in dnss if d.get("answer") == ip and d.get("query")})


def enriquecer_con_dns(candidatos: list[dict], dnss: list[dict]) -> list[dict]:
    """Añade a cada candidato el/los dominio(s) con que se resolvió su destino."""
    for c in candidatos:
        c["dominios"] = dominios_de_ip(dnss, c["dst"])
    return candidatos


def resumen_candidatos(candidatos: list[dict], top: int = 5) -> list[dict]:
    """Vista compacta de los candidatos más periódicos, para el agente/LLM."""
    campos = ("src", "dst", "dst_externo", "service", "resp_p", "dominios",
              "conexiones", "intervalo_medio_s", "cv", "periodico", "puntuacion")
    return [{k: c.get(k) for k in campos} for c in candidatos[:top] if c["periodico"]]


if __name__ == "__main__":
    base = Path(__file__).resolve().parent.parent
    conns = cargar_conn(base / "output" / "logs" / "conn.log")
    dnss = cargar_dns(base / "output" / "logs" / "dns.log")
    cands = enriquecer_con_dns(analizar_beaconing(conns), dnss)
    print(f"Conexiones: {len(conns)}  |  DNS: {len(dnss)}  |  candidatos periódicos: "
          f"{sum(1 for c in cands if c['periodico'])}\n")
    print(f"{'punt':>5} {'cv':>6} {'n':>4}  {'src':13} {'dst':13} {'svc':5} {'ext':>4}  dominios")
    for c in cands[:6]:
        svc = ",".join(c["service"])
        dom = ",".join(c["dominios"]) or "-"
        print(f"{c['puntuacion']:>5} {c['cv']:>6} {c['conexiones']:>4}  "
              f"{c['src']:13} {c['dst']:13} {svc:5} {str(c['dst_externo']):>4}  {dom}")
    serie = serie_temporal(conns, cands[0]["src"], cands[0]["dst"])
    print(f"\nSerie temporal del candidato top: {len(serie)} puntos "
          f"(para la gráfica de latidos).")

    # Auto-verificación: el beacon C2 debe ser el candidato de mayor puntuación.
    top = cands[0]
    assert top["src"] == "10.10.10.17" and top["dst"] == "192.0.2.66", \
        f"El beacon no quedó primero: {top['src']}->{top['dst']}"
    assert top["conexiones"] >= 50 and top["cv"] < 0.1
    # El NTP debe aparecer como periódico (candidato), no descartado por el motor.
    ntp = [c for c in cands if "ntp" in c["service"]]
    assert ntp and ntp[0]["periodico"], "El NTP debería figurar como periódico"
    print("\n[OK] El beacon C2 es el candidato top; el NTP figura como periódico "
          "(lo clasificará el agente).")
