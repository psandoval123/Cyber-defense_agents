"""Grafo de caza del Laboratorio 3 (LangGraph).

Orquesta el agente de threat hunting como un grafo de estados con un CICLO DE
REFINAMIENTO multi-fuente (más que un bucle ReAct simple):

    plan → rag → analizar → evaluar ──(refinar: trae el DNS)──► analizar
                               │
                               └──(concluir)──► veredicto → FIN

- `plan`      (LLM): formula la hipótesis de caza.
- `rag`       : recupera el conocimiento relevante (Chroma + embeddings).
- `analizar`  (determinista): puntúa el beaconing; al refinar, correlaciona DNS.
- `evaluar`   : decide si la evidencia basta o hay que refinar (traer más datos).
- `veredicto` (LLM + RAG): clasifica la amenaza, la mapea a ATT&CK y la fundamenta.

El control del flujo y el análisis numérico son deterministas; el LLM razona y
redacta, anclado en el conocimiento recuperado (anti-alucinación).
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import TypedDict

import ollama
from langgraph.graph import StateGraph, START, END

from analisis import (cargar_conn, cargar_dns, analizar_beaconing,
                      enriquecer_con_dns, resumen_candidatos)
import rag

BASE = Path(__file__).resolve().parent.parent
CONN_LOG = BASE / "output" / "logs" / "conn.log"
DNS_LOG = BASE / "output" / "logs" / "dns.log"

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://ollama:11434")
MODELO = os.getenv("LAB_MODELO", "llama3.2:3b")
TEMPERATURA = float(os.getenv("LAB_TEMPERATURA", "0"))
MAX_ITER = int(os.getenv("LAB_MAX_ITERACIONES", "6"))

_cli = ollama.Client(host=OLLAMA_HOST)


class EstadoCaza(TypedDict):
    hipotesis: str
    conocimiento: str
    dns_consultado: bool
    candidatos: list
    iteraciones: int
    decision: str
    veredicto: dict
    traza: list


def _llm_json(system: str, user: str) -> dict:
    """Llama al LLM pidiendo JSON y lo parsea con tolerancia."""
    resp = _cli.chat(
        model=MODELO,
        messages=[{"role": "system", "content": system},
                  {"role": "user", "content": user}],
        format="json",
        options={"temperature": TEMPERATURA, "num_predict": 700, "num_ctx": 4096},
    )
    txt = resp["message"]["content"].strip()
    try:
        return json.loads(txt)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", txt, re.DOTALL)
        return json.loads(m.group(0)) if m else {}


def _anota(state: EstadoCaza, **campos) -> list:
    return state.get("traza", []) + [campos]


# --- Nodos ---

def nodo_plan(state: EstadoCaza) -> dict:
    conns = cargar_conn(CONN_LOG)
    n_pares = len({(e.get("orig_h"), e.get("resp_h")) for e in conns})
    system = ("Eres un agente de threat hunting. Propón UNA hipótesis de caza "
              "para revisar tráfico de red. Responde SOLO JSON: "
              '{"hipotesis":"<frase breve>"}.')
    user = (f"Hay {len(conns)} conexiones entre {n_pares} pares origen-destino, "
            "sin alertas previas. ¿Qué amenaza oculta buscarías primero?")
    try:
        hip = _llm_json(system, user).get("hipotesis", "").strip()
    except Exception:  # noqa: BLE001
        hip = ""
    if not hip:
        hip = "Posible C2 beaconing: conexiones periódicas y regulares a un destino externo."
    print(f"[plan] 🧠 Hipótesis: {hip}")
    return {"hipotesis": hip, "dns_consultado": False, "iteraciones": 0,
            "traza": _anota(state, nodo="plan", hipotesis=hip)}


def nodo_rag(state: EstadoCaza) -> dict:
    conocimiento = rag.contexto_para_prompt(state["hipotesis"], k=3)
    fuentes = [t["fuente"] for t in rag.recuperar(state["hipotesis"], k=3)]
    print(f"[rag] 📚 Conocimiento recuperado: {fuentes}")
    return {"conocimiento": conocimiento,
            "traza": _anota(state, nodo="rag", fuentes=fuentes)}


def nodo_analizar(state: EstadoCaza) -> dict:
    conns = cargar_conn(CONN_LOG)
    cands = analizar_beaconing(conns)
    if state.get("dns_consultado"):
        cands = enriquecer_con_dns(cands, cargar_dns(DNS_LOG))
    periodicos = [c for c in cands if c["periodico"]]
    print(f"[analizar] ⚙️ {len(periodicos)} candidatos periódicos "
          f"(DNS={'sí' if state.get('dns_consultado') else 'no'})")
    return {"candidatos": cands,
            "traza": _anota(state, nodo="analizar", periodicos=len(periodicos),
                            dns=state.get("dns_consultado", False))}


def nodo_evaluar(state: EstadoCaza) -> dict:
    cands = state.get("candidatos", [])
    periodicos = [c for c in cands if c.get("periodico")]
    top = periodicos[0] if periodicos else None
    # Refina UNA vez: si aún no hemos traído el DNS y al candidato principal le
    # falta contexto de dominio, buscamos más evidencia (segunda fuente).
    falta_dns = not state.get("dns_consultado")
    sin_dominio = not (top and top.get("dominios"))
    if falta_dns and sin_dominio and state.get("iteraciones", 0) < MAX_ITER:
        print("[evaluar] 🔁 Evidencia insuficiente → refinar con correlación DNS")
        return {"decision": "refinar", "dns_consultado": True,
                "iteraciones": state.get("iteraciones", 0) + 1,
                "traza": _anota(state, nodo="evaluar", decision="refinar")}
    print("[evaluar] ✓ Evidencia suficiente → concluir")
    return {"decision": "concluir",
            "traza": _anota(state, nodo="evaluar", decision="concluir")}


def nodo_veredicto(state: EstadoCaza) -> dict:
    periodicos = resumen_candidatos(state.get("candidatos", []), top=5)
    system = (
        "Eres un agente de threat hunting. Clasifica los candidatos PERIÓDICOS "
        "usando SOLO el conocimiento proporcionado. Reglas:\n"
        "- NTP al puerto 123 hacia un servidor de tiempo es BENIGNO, aunque sea "
        "el MÁS regular: enuméralo en 'benignos_descartados'.\n"
        "- Un canal ssl/443 sostenido a una IP externa con dominio sospechoso es "
        "el C2 (la amenaza). El 'host_comprometido' es el ORIGEN (src) y el C2 es "
        "el DESTINO (dst) con su dominio.\n"
        "- En 'tecnicas' usa EXCLUSIVAMENTE identificadores MITRE ATT&CK que "
        "aparezcan en el CONOCIMIENTO (por ejemplo T1071.001, T1571). No inventes "
        "técnicas ni uses nombres de archivo.\n"
        "Responde SOLO JSON: {\"amenaza_encontrada\":true/false,"
        "\"host_comprometido\":\"<ip origen>\",\"c2_ip\":\"<ip destino>\","
        "\"c2_dominio\":\"<dominio>\",\"tecnicas\":[\"T1071.001\"],"
        "\"benignos_descartados\":[\"<ip>\"],\"playbook\":\"<archivo citado>\","
        "\"resumen\":\"2-3 frases\"}.")
    user = (f"CONOCIMIENTO:\n{state['conocimiento']}\n\n"
            f"CANDIDATOS PERIÓDICOS (src=origen, dst=destino):\n"
            f"{json.dumps(periodicos, ensure_ascii=False)}")
    try:
        ver = _llm_json(system, user)
    except Exception as exc:  # noqa: BLE001
        ver = {"amenaza_encontrada": False, "error": str(exc)}
    print(f"[veredicto] 🎯 host={ver.get('host_comprometido','?')} "
          f"C2={ver.get('c2_ip','?')} ({ver.get('c2_dominio','?')}) "
          f"amenaza={ver.get('amenaza_encontrada')}")
    return {"veredicto": ver,
            "traza": _anota(state, nodo="veredicto", veredicto=ver)}


def _ruta_tras_evaluar(state: EstadoCaza) -> str:
    return state.get("decision", "concluir")


def construir_grafo():
    g = StateGraph(EstadoCaza)
    g.add_node("plan", nodo_plan)
    g.add_node("rag", nodo_rag)
    g.add_node("analizar", nodo_analizar)
    g.add_node("evaluar", nodo_evaluar)
    g.add_node("veredicto", nodo_veredicto)
    g.add_edge(START, "plan")
    g.add_edge("plan", "rag")
    g.add_edge("rag", "analizar")
    g.add_edge("analizar", "evaluar")
    g.add_conditional_edges("evaluar", _ruta_tras_evaluar,
                            {"refinar": "analizar", "concluir": "veredicto"})
    g.add_edge("veredicto", END)
    return g.compile()
