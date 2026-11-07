"""Dashboard del Laboratorio 3 — threat hunting con agente (Streamlit).

Interfaz visual para ejecutar la cacería y VER al agente trabajar: fuentes de
datos, pasos del grafo LangGraph en vivo, la gráfica de los "latidos" del beacon
y el veredicto fundamentado.

Lanzar (dentro del contenedor hunter):
    streamlit run ui/app.py --server.address 0.0.0.0 --server.port 8501
"""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

# Los módulos del agente viven en ../agente.
BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE / "agente"))

import analisis  # noqa: E402
import grafo  # noqa: E402

CONN_LOG = BASE / "output" / "logs" / "conn.log"
DNS_LOG = BASE / "output" / "logs" / "dns.log"

st.set_page_config(page_title="Lab 3 · Threat Hunting", page_icon="🛰️", layout="wide")

# --- Encabezado ---
st.title("🛰️ Laboratorio 3 — Caza de C2 Beaconing con agente")
st.caption("Agente proactivo (LangGraph + RAG + LLM local) que busca una amenaza "
           "que evade las firmas: un canal de mando y control oculto en el tráfico.")

# --- Carga de datos ---
if not CONN_LOG.exists():
    st.warning("No hay logs todavía. Genera el tráfico sintético: "
               "`python3 datos/generar_trafico.py`")
    st.stop()

conns = analisis.cargar_conn(CONN_LOG)
dnss = analisis.cargar_dns(DNS_LOG) if DNS_LOG.exists() else []
candidatos = analisis.enriquecer_con_dns(analisis.analizar_beaconing(conns), dnss)
periodicos = [c for c in candidatos if c["periodico"]]

# --- Panel de fuentes de datos ---
st.subheader("1 · Fuentes de datos (estilo Zeek)")
c1, c2, c3, c4 = st.columns(4)
c1.metric("Conexiones", f"{len(conns):,}")
c2.metric("Consultas DNS", f"{len(dnss):,}")
c3.metric("Pares origen→destino", len({(e['orig_h'], e['resp_h']) for e in conns}))
c4.metric("Candidatos periódicos", len(periodicos))

# --- Control ---
with st.sidebar:
    st.header("Control de la cacería")
    st.write("El agente formula una hipótesis, consulta la base de conocimiento, "
             "analiza la periodicidad, refina con el DNS y emite un veredicto.")
    ejecutar = st.button("▶ Ejecutar cacería", type="primary", use_container_width=True)
    st.divider()
    st.caption("Modelo y parámetros se configuran en `.env` (LLM local vía Ollama).")

# --- Ejecución del grafo, paso a paso ---
st.subheader("2 · Razonamiento del agente (grafo LangGraph)")
if ejecutar:
    etiquetas = {
        "plan": "🧠 Formula la hipótesis de caza",
        "rag": "📚 Recupera conocimiento (playbooks)",
        "analizar": "⚙️ Analiza la periodicidad",
        "evaluar": "🔁 Evalúa la evidencia (¿refinar?)",
        "veredicto": "🎯 Emite el veredicto",
    }
    g = grafo.construir_grafo()
    veredicto = {}
    with st.status("Cazando…", expanded=True) as status:
        for paso in g.stream({"traza": []}):
            for nodo, actualizacion in paso.items():
                st.write(f"**{etiquetas.get(nodo, nodo)}**")
                if nodo == "plan":
                    st.caption(actualizacion.get("hipotesis", ""))
                elif nodo == "rag":
                    tr = actualizacion.get("traza", [])
                    if tr:
                        st.caption("Fuentes: " + ", ".join(tr[-1].get("fuentes", [])))
                elif nodo == "evaluar":
                    st.caption(f"Decisión: {actualizacion.get('decision', '')}")
                elif nodo == "veredicto":
                    veredicto = actualizacion.get("veredicto", {})
        status.update(label="Cacería completada", state="complete")
    st.session_state["veredicto"] = veredicto
else:
    st.info("Pulsa «Ejecutar cacería» en la barra lateral para ver al agente trabajar.")

# --- Gráfica de latidos ---
st.subheader("3 · Evidencia visual — línea de tiempo de conexiones")
st.caption("Cada punto es una conexión. Un beacon se delata por su espaciado "
           "regular (los “latidos”); el tráfico normal es irregular.")
filas = []
t0 = min(e["ts"] for e in conns)
for c in periodicos:
    etiqueta = f"{c['src']} → {c['dst']} ({','.join(c['service'])})"
    for ts in analisis.serie_temporal(conns, c["src"], c["dst"]):
        filas.append({"candidato": etiqueta, "minuto": (ts - t0) / 60})
if filas:
    df = pd.DataFrame(filas)
    fig = px.scatter(df, x="minuto", y="candidato", color="candidato",
                     labels={"minuto": "Minutos desde el inicio", "candidato": ""},
                     height=260)
    fig.update_traces(marker={"size": 9})
    fig.update_layout(showlegend=False, margin={"l": 0, "r": 0, "t": 10, "b": 0})
    st.plotly_chart(fig, use_container_width=True)

# --- Tabla de candidatos ---
st.subheader("4 · Candidatos periódicos")
tabla = pd.DataFrame([{
    "origen": c["src"], "destino": c["dst"], "servicio": ",".join(c["service"]),
    "puerto": ",".join(map(str, c["resp_p"])), "externo": c["dst_externo"],
    "dominio": ",".join(c.get("dominios") or []) or "—",
    "conexiones": c["conexiones"], "intervalo_s": c["intervalo_medio_s"],
    "CV": c["cv"], "puntuación": c["puntuacion"],
} for c in periodicos])
st.dataframe(tabla, use_container_width=True, hide_index=True)

# --- Veredicto ---
st.subheader("5 · Veredicto del agente")
ver = st.session_state.get("veredicto")
if not ver:
    st.caption("Aún sin veredicto. Ejecuta la cacería.")
elif ver.get("amenaza_encontrada"):
    st.error("🚨 Amenaza encontrada: C2 beaconing")
    v1, v2, v3 = st.columns(3)
    v1.metric("Host comprometido", ver.get("host_comprometido", "n/d"))
    v2.metric("C2 (destino)", ver.get("c2_ip", "n/d"))
    v3.metric("Dominio C2", ver.get("c2_dominio", "n/d"))
    st.markdown(f"**Técnicas MITRE ATT&CK:** {', '.join(ver.get('tecnicas', [])) or '—'}")
    st.markdown(f"**Descartados como benignos:** "
                f"{', '.join(ver.get('benignos_descartados', [])) or '—'}")
    if ver.get("playbook"):
        st.markdown(f"**Playbook citado (RAG):** `{ver['playbook']}`")
    st.info(ver.get("resumen", ""))
else:
    st.success("Sin amenazas confirmadas en esta cacería.")
    st.info(ver.get("resumen", ""))
