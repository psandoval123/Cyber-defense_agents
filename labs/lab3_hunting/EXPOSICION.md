# Guion de exposición — Lab 3 (threat hunting con agente)

Guion para presentar el Lab 3 en vivo, usando el **dashboard Streamlit** como
estrella. Preséntalo después de los Labs 1 y 2 (la narrativa es
"detectar → contener → **cazar lo que nadie vio**"). Prepara el entorno ANTES.

---

## 0. Antes de la exposición (una sola vez, con internet)

```bash
cd labs/lab3_hunting
cp .env.example .env
docker compose up -d --build
docker compose exec ollama ollama pull llama3.2:3b     # o reutiliza el del Lab 1 (README)
docker compose exec ollama ollama pull nomic-embed-text
docker compose exec hunter python3 datos/generar_trafico.py
docker compose exec hunter python3 agente/rag.py        # indexa el conocimiento
```

**Libera RAM:** detén los otros labs para que el modelo quepa en memoria:

```bash
cd ../lab1_deteccion && docker compose stop
cd ../lab2_respuesta && docker compose stop
cd ../lab3_hunting
```

**Corrida de calentamiento** (deja el modelo en RAM; la primera es lenta):

```bash
docker compose exec hunter python3 agente/hunter.py >/dev/null 2>&1
```

**Lanza el dashboard y déjalo abierto:**

```bash
docker compose exec -d hunter streamlit run ui/app.py \
    --server.address 0.0.0.0 --server.port 8501 --server.headless true
open http://localhost:8501
```

---

## 1. Discurso de apertura (1 min)

- **El salto:** "Hasta ahora reaccionábamos a alertas. Pero los ataques más
  peligrosos **no disparan ninguna alerta**. El hunting es **buscar** la amenaza
  que evade las firmas."
- **El caso:** un C2 *beaconing* — una máquina comprometida que 'llama a casa' a
  intervalos regulares. Cada conexión parece normal; solo el **patrón** la delata.
- **El reto extra:** hay tráfico legítimo (NTP) **aún más regular** que el beacon.
  El agente tendrá que **razonar**, no solo medir.

## 2. Mostrar el dashboard (⭐ todo ocurre aquí)

Con http://localhost:8501 proyectado:

1. **Fuentes de datos:** "955 conexiones, 655 DNS. Entre todo esto, hay un beacon
   escondido."
2. **La gráfica de latidos (sección 3):** señala el beacon —una línea **densa y
   perfectamente regular**— frente al resto. "Esto es el latido del C2."
3. **La tabla (sección 4):** el beacon es ssl/443 a una IP externa con dominio
   sospechoso; el NTP es puerto 123 a un servidor de tiempo. "Los dos son
   periódicos; solo uno es una amenaza."

## 3. Ejecutar la cacería en vivo (⭐ ~1 min)

Pulsa **«Ejecutar cacería»**. Narra los pasos del grafo según aparecen:
- 🧠 **plan:** el agente formula la hipótesis.
- 📚 **RAG:** recupera los playbooks de caza (conocimiento experto).
- ⚙️ **analizar:** mide la periodicidad.
- 🔁 **evaluar → refinar:** "no le basta con las conexiones, así que **trae una
  segunda fuente: el DNS**." (este es el razonamiento multi-paso)
- 🎯 **veredicto:** amenaza encontrada.

## 4. El veredicto (sección 5)

Señala: **host comprometido 10.10.10.17**, **C2 192.0.2.66**, dominio
`cdn-sync-telemetry.net`, técnica **T1071.001**. "Encontró el C2, lo mapeó a
ATT&CK y **descartó el NTP** — no un simple umbral, sino criterio."

## 5. Las métricas (cierre con datos)

```bash
python3 scripts/calcular_metricas.py
```

Explica: **recall de caza** (encontró el beacon), **falsos positivos 0** (no cayó
en el NTP), **cobertura ATT&CK**, **iteraciones del grafo** (el refinamiento) y
**reproducibilidad**.

## 6. Preguntas probables del jurado

- **¿Qué aporta sobre el IDS?** El IDS no ve el beacon (ninguna firma salta). El
  agente lo encuentra por el patrón + conocimiento. Es proactivo, no reactivo.
- **¿Por qué LangGraph y no un bucle simple?** Por el **ciclo de refinamiento**:
  el agente decide si le falta evidencia y busca más (el DNS). Es razonamiento
  multi-paso con estado, no una sola pasada.
- **¿Para qué el RAG?** Para **fundamentar** las decisiones en conocimiento
  experto y no alucinar (p. ej. saber que NTP:123 es benigno, citar el playbook).
- **¿Y si el modelo se equivoca?** El análisis numérico es determinista; el LLM
  solo clasifica y redacta. Las métricas (falsos positivos, recall) lo controlan.
- **Límites:** con un modelo de 3B en CPU la hipótesis sale algo ruidosa y la
  cobertura ATT&CK no siempre es total; con un modelo mayor o GPU mejora.

## 7. Reinicio limpio entre ensayos

```bash
rm -rf output/metricas_hunt output/informes_hunt output/trazas_hunt
```

## 8. Apagar

```bash
docker compose down
```
