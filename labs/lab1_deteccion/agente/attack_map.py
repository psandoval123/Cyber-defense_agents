"""Mini base de conocimiento MITRE ATT&CK para el Lab 1.

Mapea las técnicas de reconocimiento que el laboratorio puede detectar. El
agente la usa a través de la herramienta `enriquecer_attack` para no alucinar
identificadores de técnicas.
"""

from __future__ import annotations

ATTACK: dict[str, dict[str, str]] = {
    "T1046": {
        "nombre": "Network Service Discovery",
        "tactica": "Discovery (TA0007)",
        "descripcion": "Enumeración de puertos y servicios para identificar la "
                       "superficie expuesta de un host.",
    },
    "T1595.003": {
        "nombre": "Active Scanning: Wordlist Scanning",
        "tactica": "Reconnaissance (TA0043)",
        "descripcion": "Enumeración de rutas/directorios web mediante "
                       "diccionarios (fuerza bruta de rutas).",
    },
    "T1592.002": {
        "nombre": "Gather Victim Host Information: Software",
        "tactica": "Reconnaissance (TA0043)",
        "descripcion": "Fingerprinting de tecnologías y software de la víctima.",
    },
    "T1018": {
        "nombre": "Remote System Discovery",
        "tactica": "Discovery (TA0007)",
        "descripcion": "Descubrimiento de otros hosts alcanzables en la red.",
    },
}


def buscar_tecnica(tid: str) -> dict[str, str]:
    """Devuelve la ficha de una técnica, o una ficha 'desconocida'."""
    tid = (tid or "").strip().upper()
    if tid in ATTACK:
        return {"tecnica": tid, **ATTACK[tid]}
    return {
        "tecnica": tid or "desconocida",
        "nombre": "Desconocida",
        "tactica": "n/d",
        "descripcion": "Técnica no presente en la base de conocimiento del Lab 1.",
    }
