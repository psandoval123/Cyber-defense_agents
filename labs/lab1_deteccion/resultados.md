# Lab 1 — Resultados

> Resultados de una ejecución real del laboratorio. Las cifras provienen de
> `output/` y del script `scripts/calcular_metricas.py` (docs/05_evaluacion.md).
> Reejecuta el laboratorio para reproducirlas; pueden variar ligeramente por el
> carácter no determinista del LLM.

## 1. Entorno

| Dato | Valor |
|---|---|
| Fecha de ejecución | 2026-10-25 |
| Host (SO / RAM / CPU) | macOS 26.5.2 · 16 GB · Apple M5 (10 núcleos) |
| Versión Docker / Compose | 29.3.1 / v5.1.1 |
| Modelo LLM (`LAB_MODELO`) | `llama3.2:3b` (Ollama, CPU) |
| Nº de corridas del agente (n) | 3 |

## 2. Línea base — reconocimiento observado

Técnicas ejecutadas por el adversario emulado (ground truth): `T1046`,
`T1592.002`, `T1595.003`. El sensor generó **10.252 alertas**.

| Técnica | Herramienta | ¿Generó alerta en Suricata? | Nº de alertas |
|---|---|---|---|
| T1046 (escaneo de puertos/servicios) | nmap | Sí | 7.927 (SYN scan) + 4 (NSE) |
| T1592.002 (fingerprinting web) | whatweb | Sí | 1 |
| T1595.003 (enumeración de rutas) | gobuster | Sí | 1.188 (gobuster) + 1.107 (404) |

> El fingerprinting (whatweb) produce **una sola** alerta: es la señal más débil
> y, de hecho, la que el agente con modelo pequeño tiende a no reportar.

## 3. Métricas del agente (n = 3 corridas)

Salida de `python3 scripts/calcular_metricas.py`:

| Métrica | Valor |
|---|---|
| MTTD (inicio ataque → primera alerta) | **0,15 s** |
| Cobertura MITRE ATT&CK (sensor) | **100 %** (3/3 técnicas alertadas) |
| Precisión (prom.) | **1,00** |
| Recall (prom.) | **0,67** (2/3 técnicas reportadas por el agente) |
| F1 (prom.) | **0,80** |
| Falsos positivos | **0** (ninguna técnica reportada fuera del ground truth) |
| Nivel de automatización | **100 %** (sin intervención manual) |
| Reproducibilidad | **100 %** (veredicto `reconocimiento` estable en las 3) |

### Detalle por corrida

| Corrida | Veredicto | Precisión | Recall | F1 | Pasos | Duración (s) |
|---|---|---|---|---|---|---|
| 12:25:10Z | reconocimiento | 1,00 | 0,67 | 0,80 | 5 | 107,8 |
| 12:26:58Z | reconocimiento | 1,00 | 0,67 | 0,80 | 5 | 119,5 |
| 12:28:58Z | reconocimiento | 1,00 | 0,67 | 0,80 | 5 | 140,1 |

## 4. Análisis

**Detección y precisión**
- El sensor detectó las **3 técnicas** (cobertura 100 %). El agente confirmó
  **2 de 3** (`T1046` y `T1595.003`), de forma estable en las 3 corridas.
- Se le escapó `T1592.002` (whatweb): es la señal más débil (1 sola alerta
  frente a miles del escaneo), eclipsada por el volumen del resto. Esto explica
  el recall de 0,67 con precisión perfecta (0 falsos positivos).
- No hubo alucinaciones: nunca reportó técnicas inexistentes.

**Comportamiento del agente**
- Siguió el orden esperado: `consultar_alertas` → `enriquecer_attack` (×2) →
  `crear_caso` → `generar_informe`, cerrando en **5 pasos**.
- Comportamiento idéntico entre corridas (temperatura 0 + protocolo JSON),
  clave para la reproducibilidad.
- Coste: ~1,8–2,3 min por corrida en **CPU** (Apple M5). Con GPU o un modelo
  servido en la nube sería de segundos.

**Perspectiva defensiva (blue team)**
- MTTD de **0,15 s**: el escaneo se delata casi instantáneamente por el volumen
  de SYN; detección muy temprana.
- Recomendaciones que propuso el agente en los informes: *rate limiting*,
  ocultar *banners* de software y reducir/analizar la superficie expuesta.
- Mejora propuesta para subir el recall: instruir al agente para enumerar
  explícitamente **todas** las firmas distintas (no solo las de mayor volumen),
  o usar un modelo mayor; así capturaría también `T1592.002`.

## 5. Evidencias

- `output/suricata/eve.json` — 10.252 alertas del sensor (+ `fast.log`, `stats.log`).
- `output/atacante/recon-*.jsonl` — timeline del adversario emulado.
- `output/trazas/traza-*.jsonl` — razonamiento paso a paso del agente (3).
- `output/casos/CASO-*.json` — casos de incidente abiertos (3).
- `output/informes/informe-*.md` — informes finales con recomendaciones (3).
- `output/metricas/run-*.json` y `output/metricas/resumen.json` — métricas.
