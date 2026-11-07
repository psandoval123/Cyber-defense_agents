# Lab 3 — Resultados

> Resultados de una ejecución real. Las cifras provienen de `output/` y de
> `scripts/calcular_metricas.py` (docs/05_evaluacion.md). Reejecuta para
> reproducir; pueden variar por el carácter no determinista del LLM.

## 1. Entorno

| Dato | Valor |
|---|---|
| Fecha de ejecución | 2026-11-07 |
| Host (SO / RAM / CPU) | macOS 26.5.2 · 16 GB · Apple M5 (10 núcleos) |
| Versión Docker / Compose | 29.3.1 / v5.1.1 |
| Modelos (razonamiento / embeddings) | `llama3.2:3b` / `nomic-embed-text` (Ollama, CPU) |
| Nº de corridas (n) | 3 |

## 2. Escenario (datos sintéticos)

- **955 conexiones** y **655 consultas DNS** (formato estilo Zeek), ventana de 1 h.
- **Beacon oculto (amenaza):** `10.10.10.17 → 192.0.2.66` (ssl/443), dominio
  `cdn-sync-telemetry.net`, cada ~60 s, 60 latidos, CV 0,03.
- **Señuelo (benigno):** NTP `10.10.10.11/12 → 200.16.0.2` (123), **CV 0,003** —
  *más* regular que el beacon.
- Resto: navegación web irregular (ruido).

## 3. Métricas (n = 3)

| Métrica | Valor |
|---|---|
| **Recall de caza** | **100 %** (3/3: identificó host, C2 y dominio correctos) |
| **Falsos positivos** | **0** (nunca marcó el NTP como amenaza) |
| **Cobertura MITRE ATT&CK** | **0,50** (siempre T1071.001; omitió T1571) |
| **Iteraciones del grafo** | **1,0** (un refinamiento con DNS en cada corrida) |
| **Tiempo de caza (prom.)** | **58,3 s** |
| **Recuperación RAG relevante** | **100 %** (beaconing.md recuperado en las 3) |
| **Cita explícita del playbook** | **0 %** (el modelo no rellenó el campo) |
| **Reproducibilidad** | **100 %** (veredicto estable en las 3) |

### Detalle por corrida

| Corrida | Recall | FP | Cobertura ATT&CK | Iteraciones | Tiempo (s) | C2 detectado |
|---|---|---|---|---|---|---|
| 19:31:57Z | 1 | 0 | 0,50 | 1 | 52,8 | 192.0.2.66 |
| 19:32:51Z | 1 | 0 | 0,50 | 1 | 57,7 | 192.0.2.66 |
| 19:33:49Z | 1 | 0 | 0,50 | 1 | 64,4 | 192.0.2.66 |

## 4. Análisis

**Detección y criterio**
- El agente **encontró el beacon** en las 3 corridas (host 10.10.10.17, C2
  192.0.2.66, dominio `cdn-sync-telemetry.net`) y lo mapeó a **T1071.001**.
- **0 falsos positivos:** descartó el NTP pese a ser *más* periódico que el
  beacon. Es el resultado clave: el agente **razonó** (puerto/servicio/dominio),
  no aplicó un simple umbral de periodicidad.

**Razonamiento multi-paso (LangGraph)**
- En cada corrida se activó el **ciclo de refinamiento**: con las conexiones no
  bastó, el agente **trajo el DNS** (segunda fuente) y recién ahí concluyó. Eso
  es razonamiento con estado, no una sola pasada.

**Fundamentación (RAG)**
- El RAG **recuperó el playbook correcto** (`beaconing.md`) en las 3 corridas
  (verificable en `output/trazas_hunt/`). La **cita explícita** del archivo en el
  veredicto fue inconsistente (0/3 aquí): el modelo de 3B no siempre rellena ese
  campo, aunque el conocimiento sí se inyectó y guió la decisión.

**Límites (honestos)**
- **Cobertura ATT&CK 0,50:** acertó T1071.001 pero omitió T1571. Un modelo mayor
  o un prompt más guiado lo mejoraría.
- **Hipótesis inicial ruidosa:** el modelo pequeño divaga al formularla; es
  cosmético (no afecta el veredicto), pero ensucia la recuperación RAG.
- **Tiempo (~58 s) en CPU:** dominado por la inferencia del LLM; con GPU bajaría.

## 5. Evidencias

- `output/logs/conn.log`, `output/logs/dns.log` — tráfico sintético (regenerable).
- `output/ground_truth.json` — la verdad para medir.
- `output/chroma/` — base vectorial del RAG (regenerable).
- `output/trazas_hunt/traza-*.jsonl` — pasos del grafo (trazabilidad).
- `output/informes_hunt/informe-*.md` — informes de caza.
- `output/metricas_hunt/run-*.json` y `resumen.json` — métricas.
- Captura del dashboard Streamlit (demo visual).
