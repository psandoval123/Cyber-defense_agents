"""RAG del Laboratorio 3: base de conocimiento de caza con Chroma + Ollama.

Indexa los playbooks de `conocimiento/` en una base vectorial **Chroma**
(persistente, embebida) usando **embeddings locales de Ollama**
(`nomic-embed-text`). El agente recupera el conocimiento relevante para
fundamentar sus decisiones (anti-alucinación) y el mapeo MITRE ATT&CK.

Cada documento Markdown se trocea por secciones `##` para una recuperación
más precisa.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path

# Silencia la telemetría de Chroma (un bug conocido imprime warnings inofensivos).
os.environ.setdefault("ANONYMIZED_TELEMETRY", "False")
logging.getLogger("chromadb.telemetry").setLevel(logging.CRITICAL)

import chromadb
import ollama

BASE = Path(__file__).resolve().parent.parent
CONOCIMIENTO_DIR = BASE / "conocimiento"
CHROMA_DIR = BASE / "output" / "chroma"

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://ollama:11434")
EMBED_MODEL = os.getenv("LAB_EMBED_MODEL", "nomic-embed-text")
COLECCION = "hunting_kb"

_cliente_ollama = ollama.Client(host=OLLAMA_HOST)

# Desactiva la telemetría de Chroma (evita warnings ruidosos en la demo).
_SETTINGS = chromadb.Settings(anonymized_telemetry=False)


def _cliente_chroma() -> "chromadb.ClientAPI":
    return chromadb.PersistentClient(path=str(CHROMA_DIR), settings=_SETTINGS)


def _embed(textos: list[str]) -> list[list[float]]:
    """Embeddings locales vía Ollama."""
    vectores = []
    for t in textos:
        resp = _cliente_ollama.embeddings(model=EMBED_MODEL, prompt=t)
        vectores.append(resp["embedding"])
    return vectores


def _trocear(md: str, fuente: str) -> list[dict]:
    """Divide un documento Markdown por secciones de nivel 2 (##)."""
    partes = re.split(r"\n(?=## )", md.strip())
    chunks = []
    for i, parte in enumerate(partes):
        texto = parte.strip()
        if not texto:
            continue
        titulo = texto.splitlines()[0].lstrip("# ").strip()
        chunks.append({
            "id": f"{fuente}#{i}",
            "texto": texto,
            "fuente": fuente,
            "titulo": titulo,
        })
    return chunks


def cargar_chunks() -> list[dict]:
    chunks = []
    for ruta in sorted(CONOCIMIENTO_DIR.glob("*.md")):
        chunks.extend(_trocear(ruta.read_text(encoding="utf-8"), ruta.name))
    return chunks


def _coleccion():
    return _cliente_chroma().get_or_create_collection(COLECCION)


def indexar(reindexar: bool = True) -> int:
    """Indexa (o reindexa) los playbooks en Chroma. Devuelve el nº de chunks."""
    CHROMA_DIR.mkdir(parents=True, exist_ok=True)
    cliente = _cliente_chroma()
    if reindexar:
        try:
            cliente.delete_collection(COLECCION)
        except Exception:  # noqa: BLE001
            pass
    col = cliente.get_or_create_collection(COLECCION)
    chunks = cargar_chunks()
    embeddings = _embed([c["texto"] for c in chunks])
    col.upsert(
        ids=[c["id"] for c in chunks],
        embeddings=embeddings,
        documents=[c["texto"] for c in chunks],
        metadatas=[{"fuente": c["fuente"], "titulo": c["titulo"]} for c in chunks],
    )
    return len(chunks)


def recuperar(consulta: str, k: int = 3) -> list[dict]:
    """Recupera los k chunks más relevantes para una consulta."""
    col = _coleccion()
    if col.count() == 0:
        indexar()
        col = _coleccion()
    q = _embed([consulta])
    res = col.query(query_embeddings=q, n_results=k)
    salida = []
    for doc, meta, dist in zip(res["documents"][0], res["metadatas"][0],
                               res["distances"][0]):
        salida.append({
            "fuente": meta.get("fuente"),
            "titulo": meta.get("titulo"),
            "texto": doc,
            "distancia": round(dist, 4),
        })
    return salida


def contexto_para_prompt(consulta: str, k: int = 3) -> str:
    """Devuelve el conocimiento recuperado listo para inyectar en el prompt."""
    trozos = recuperar(consulta, k)
    bloques = [f"[{t['fuente']} · {t['titulo']}]\n{t['texto']}" for t in trozos]
    return "\n\n---\n\n".join(bloques)


if __name__ == "__main__":
    n = indexar()
    print(f"[OK] Indexados {n} chunks de {CONOCIMIENTO_DIR}\n")
    for consulta in [
        "conexiones regulares a un destino externo con dominio sospechoso",
        "tráfico NTP periódico al puerto 123, ¿es malicioso?",
        "muchas consultas DNS largas y aleatorias",
    ]:
        print(f"CONSULTA: {consulta}")
        for t in recuperar(consulta, k=2):
            print(f"   → {t['fuente']} · {t['titulo']}  (dist {t['distancia']})")
        print()
    # Auto-verificación: la consulta de beaconing debe recuperar su playbook.
    top = recuperar("beaconing regular hacia C2 externo", k=1)[0]
    assert top["fuente"] == "beaconing.md", f"Recuperó {top['fuente']}, no beaconing.md"
    print("[OK] La recuperación semántica devuelve el playbook correcto.")
