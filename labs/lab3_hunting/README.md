# Laboratorio 3 — Threat Hunting proactivo con agente

> Tercer laboratorio, lado **AZUL (defensivo)**. A diferencia de los Labs 1 y 2
> (reactivos), aquí **no hay alerta**: un agente de IA **busca** proactivamente una
> amenaza que **evade las firmas** — un canal de C2 *beaconing* oculto en el
> tráfico. Combina un **grafo LangGraph** (razonamiento multi-paso con ciclo de
> refinamiento), **RAG** (base de conocimiento en Chroma con embeddings locales),
> un **motor de análisis** determinista y un **dashboard Streamlit**. Diseño
> completo en [DISENO.md](DISENO.md).

---

## 1. Contexto

El *beaconing* es el "latido" de una máquina comprometida que contacta a su C2 a
intervalos regulares. Cada conexión parece normal, por lo que **ningún IDS la
detecta**: solo el **patrón temporal** la delata. El agente debe encontrarlo y,
además, **no confundirlo** con tráfico legítimo también periódico (NTP) — es
decir, **razonar**, no solo medir.

**Técnicas MITRE ATT&CK:** T1071.001 (C2 web), T1571 (puerto no estándar).

## 2. Objetivos de aprendizaje

- **Ejecutar** una cacería proactiva automatizada sobre logs de red. *(Aplicar)*
- **Analizar** cómo un agente multi-paso (LangGraph) orquesta análisis + RAG + LLM. *(Analizar)*
- **Evaluar** recall de caza, falsos positivos, cobertura ATT&CK y fundamentación. *(Evaluar)*
- **Discutir** el valor del hunting frente a la detección por firmas. *(Crear)*

## 3. Arquitectura

```
Generador sintético → conn.log + dns.log (estilo Zeek)
        → Agente de hunting (LangGraph):
            plan → RAG (Chroma) → analizar → evaluar ─(refina: DNS)─► analizar
                                                   └─(concluir)─► veredicto
        → Dashboard Streamlit (se ve el proceso + la gráfica de latidos)
```

- El **análisis numérico** (periodicidad) es determinista; el **LLM** razona y
  redacta anclado en el conocimiento recuperado (anti-alucinación).

## 4. Requisitos

- Docker y Docker Compose; **~7 GB RAM libres** (conviene detener los Labs 1-2).
- Dos modelos locales en Ollama: `llama3.2:3b` y `nomic-embed-text` (sin claves).
- Puerto `8501` libre para el dashboard.

## 5. Montaje

```bash
cd labs/lab3_hunting
cp .env.example .env
docker compose up -d --build
docker compose exec ollama ollama pull llama3.2:3b
docker compose exec ollama ollama pull nomic-embed-text
```

> **Reutilizar el modelo del Lab 1** (evita re-descargar 2 GB):
> ```bash
> docker run --rm -v lab1_deteccion_ollama_models:/from \
>   -v lab3_hunting_ollama_models:/to alpine sh -c "cp -a /from/. /to/"
> docker compose restart ollama
> ```

## 6. Desarrollo

**6.1. Genera el tráfico sintético** (incluye el beacon oculto + el señuelo NTP):

```bash
docker compose exec hunter python3 datos/generar_trafico.py
```

**6.2. Indexa la base de conocimiento en Chroma** (también se hace solo en la
primera cacería):

```bash
docker compose exec hunter python3 agente/rag.py
```

**6.3. Ejecuta una cacería por línea de comandos:**

```bash
docker compose exec hunter python3 agente/hunter.py
```

**6.4. Lanza el dashboard visual** (⭐ la demo):

```bash
docker compose exec -d hunter streamlit run ui/app.py \
    --server.address 0.0.0.0 --server.port 8501 --server.headless true
# Abre http://localhost:8501 y pulsa «Ejecutar cacería»
```

## 7. Métricas

```bash
python3 scripts/calcular_metricas.py
```

Calcula recall de caza, falsos positivos, cobertura ATT&CK, iteraciones del
grafo, fundamentación RAG y reproducibilidad. Registra todo en
[resultados.md](resultados.md).

## 8. Entregables

1. Dashboard Streamlit funcional (demo visual).
2. `resultados.md` con métricas reales y análisis.
3. `output/` con trazas, informes y métricas.

## 9. Limpieza

```bash
docker compose down -v --rmi all
```

## Estructura de la carpeta

```
lab3_hunting/
├── DISENO.md / README.md / EXPOSICION.md / resultados.md
├── docker-compose.yml / Dockerfile / requirements.txt / .env.example
├── datos/generar_trafico.py      # genera conn.log, dns.log, ground_truth.json
├── conocimiento/*.md             # playbooks para el RAG
├── agente/
│   ├── analisis.py               # motor de periodicidad (determinista)
│   ├── rag.py                    # Chroma + embeddings Ollama
│   ├── grafo.py                  # grafo LangGraph (ciclo de refinamiento)
│   └── hunter.py                 # ejecución por CLI
├── ui/app.py                     # dashboard Streamlit
├── scripts/calcular_metricas.py
└── output/                       # (generado) logs, chroma, trazas, informes, métricas
```

## Notas

- El bloqueo de memoria es el principal límite en CPU: el modelo usa `num_ctx`
  acotado y conviene detener los otros labs (`docker compose stop`) durante la demo.
- La base vectorial (`output/chroma`) y los logs (`*.log`) se regeneran; no se versionan.
