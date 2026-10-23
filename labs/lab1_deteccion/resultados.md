# Lab 1 — Resultados (plantilla)

> Rellena esta plantilla al ejecutar el laboratorio. **No publiques métricas sin
> haber ejecutado y verificado el escenario** (docs/05_evaluacion.md). Las cifras
> salen de `output/` y del script `scripts/calcular_metricas.py`.

## 1. Entorno

| Dato | Valor |
|---|---|
| Fecha de ejecución | |
| Host (SO / RAM / CPU) | |
| Versión Docker | |
| Modelo LLM (`LAB_MODELO`) | |
| Nº de corridas del agente (n) | |

## 2. Línea base — reconocimiento observado

Técnicas ejecutadas por el adversario emulado (ground truth): `T1046`,
`T1592.002`, `T1595.003`. Resume lo que ves en el tráfico / alertas.

| Técnica | Herramienta | ¿Generó alerta en Suricata? | Nº de alertas |
|---|---|---|---|
| T1046 (escaneo de puertos/servicios) | nmap | | |
| T1592.002 (fingerprinting web) | whatweb | | |
| T1595.003 (enumeración de rutas) | gobuster | | |

## 3. Métricas del agente (n corridas)

Pega aquí la salida de `python3 scripts/calcular_metricas.py`.

| Métrica | Valor |
|---|---|
| MTTD (inicio ataque → primera alerta) | |
| Cobertura MITRE ATT&CK (sensor) | |
| Precisión (prom.) | |
| Recall (prom.) | |
| F1 (prom.) | |
| Falsos positivos (técnicas detectadas fuera del ground truth) | |
| Nivel de automatización | |
| Reproducibilidad (veredicto estable en n corridas) | |

### Detalle por corrida

| Corrida | Veredicto | Precisión | Recall | F1 | Pasos | Duración (s) |
|---|---|---|---|---|---|---|
| | | | | | | |

## 4. Análisis (responde en prosa)

**Detección y precisión**
- ¿Detectó el agente las tres técnicas? ¿Alguna se le escapó?
- ¿Reportó técnicas que no ocurrieron (falsos positivos / alucinaciones)?
- ¿El veredicto fue estable entre corridas y entre modelos?

**Comportamiento del agente**
- ¿Qué orden siguió (consultar → enriquecer → caso → informe)?
- ¿Usó bien `enriquecer_attack` o inventó identificadores?
- ¿Cuántos pasos y cuánto tiempo necesitó en promedio?

**Perspectiva defensiva (blue team)**
- ¿Qué recomendaciones propuso el agente en el informe?
- ¿Qué añadirías tú (reglas Suricata, rate limiting, reducción de superficie)?
- ¿Qué tan temprano (MTTD) se detectó? ¿Es suficiente?

## 5. Evidencias

- `output/suricata/eve.json` — alertas del sensor.
- `output/atacante/recon-*.jsonl` — timeline del adversario emulado.
- `output/trazas/traza-*.jsonl` — razonamiento paso a paso del agente.
- `output/casos/CASO-*.json` — casos de incidente abiertos.
- `output/informes/informe-*.md` — informes finales.
- `output/metricas/` — métricas por corrida y `resumen.json`.
