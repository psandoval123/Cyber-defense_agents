# Imagen del HUNTER para el Laboratorio 3: agente (LangGraph) + RAG (Chroma) +
# interfaz (Streamlit). Embeddings y LLM corren en el servicio Ollama.
FROM python:3.12-slim

WORKDIR /lab

# Dependencias primero (mejor cacheo de capas).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Código del laboratorio (ver .dockerignore para exclusiones).
COPY . .

# Queda en espera; el agente y la UI se lanzan desde la guía.
CMD ["sleep", "infinity"]
