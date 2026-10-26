"""Enforcer del firewall (Lab 2).

Vigila el directorio de ÓRDENES que escribe el agente de respuesta y las APLICA
con iptables en el namespace de red de la víctima (que este contenedor comparte).
Mantiene la separación decisión/ejecución: el agente decide y ordena; aquí se
ejecuta, de forma idempotente, reversible y auditada.

Órdenes (output/ordenes/*.json):
    {"id","ip","accion":"block"|"unblock","estado":"pendiente",...}

El enforcer actualiza cada orden con su resultado (estado "aplicada"/"error",
marca de tiempo y la regla) y publica el estado global en output/firewall/estado.json.
Solo manipula la cadena INPUT con la IP de origen indicada: nunca ejecuta otra cosa.
"""

from __future__ import annotations

import ipaddress
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

ORDENES_DIR = Path("/output/ordenes")
ESTADO_DIR = Path("/output/firewall")
ESTADO_PATH = ESTADO_DIR / "estado.json"
INTERVALO_S = 1.0


def ahora() -> str:
    return datetime.now(timezone.utc).isoformat()


def ip_valida(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def iptables(*args: str) -> tuple[int, str]:
    proc = subprocess.run(["iptables", *args], capture_output=True, text=True)
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def regla_existe(ip: str) -> bool:
    rc, _ = iptables("-C", "INPUT", "-s", ip, "-j", "DROP")
    return rc == 0


def aplicar_bloqueo(ip: str) -> dict:
    if not regla_existe(ip):
        rc, out = iptables("-I", "INPUT", "-s", ip, "-j", "DROP")
        if rc != 0:
            return {"ok": False, "detalle": f"iptables error: {out}"}
    return {"ok": True, "regla": f"-A INPUT -s {ip} -j DROP"}


def quitar_bloqueo(ip: str) -> dict:
    # Elimina todas las copias de la regla (idempotente).
    while regla_existe(ip):
        rc, out = iptables("-D", "INPUT", "-s", ip, "-j", "DROP")
        if rc != 0:
            return {"ok": False, "detalle": f"iptables error: {out}"}
    return {"ok": True, "regla": f"(eliminada) INPUT -s {ip} -j DROP"}


def snapshot_input() -> list[str]:
    rc, out = iptables("-S", "INPUT")
    return out.splitlines() if rc == 0 else []


def publicar_estado(bloqueos: set[str]) -> None:
    ESTADO_DIR.mkdir(parents=True, exist_ok=True)
    estado = {
        "actualizado": ahora(),
        "ips_bloqueadas": sorted(bloqueos),
        "iptables_input": snapshot_input(),
    }
    ESTADO_PATH.write_text(json.dumps(estado, ensure_ascii=False, indent=2),
                           encoding="utf-8")


def procesar_orden(ruta: Path, bloqueos: set[str]) -> None:
    try:
        orden = json.loads(ruta.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return
    if orden.get("estado") != "pendiente":
        return

    ip = str(orden.get("ip", ""))
    accion = orden.get("accion", "block")

    if not ip_valida(ip):
        orden.update(estado="error", detalle=f"IP inválida: {ip!r}", aplicado=ahora())
        ruta.write_text(json.dumps(orden, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[enforcer] orden {orden.get('id')} RECHAZADA: IP inválida {ip!r}")
        return

    if accion == "block":
        res = aplicar_bloqueo(ip)
        if res["ok"]:
            bloqueos.add(ip)
    elif accion == "unblock":
        res = quitar_bloqueo(ip)
        bloqueos.discard(ip)
    else:
        res = {"ok": False, "detalle": f"acción no soportada: {accion}"}

    orden.update(
        estado="aplicada" if res["ok"] else "error",
        detalle=res.get("detalle", "ok"),
        regla=res.get("regla"),
        aplicado=ahora(),
    )
    ruta.write_text(json.dumps(orden, ensure_ascii=False, indent=2), encoding="utf-8")
    publicar_estado(bloqueos)
    estado_txt = "APLICADA" if res["ok"] else "ERROR"
    print(f"[enforcer] orden {orden.get('id')} {accion} {ip} -> {estado_txt}")


def main() -> None:
    ORDENES_DIR.mkdir(parents=True, exist_ok=True)
    bloqueos: set[str] = set()
    publicar_estado(bloqueos)
    print(f"[enforcer] firewall activo. Vigilando {ORDENES_DIR} (cada {INTERVALO_S}s).")
    while True:
        for ruta in sorted(ORDENES_DIR.glob("*.json")):
            procesar_orden(ruta, bloqueos)
        time.sleep(INTERVALO_S)


if __name__ == "__main__":
    main()
