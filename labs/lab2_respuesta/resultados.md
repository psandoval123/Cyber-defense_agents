# Lab 2 — Resultados

> Resultados de una ejecución real. Las cifras provienen de `output/` y de
> `scripts/calcular_metricas.py` (docs/05_evaluacion.md). Reejecuta para
> reproducir; pueden variar ligeramente por el carácter no determinista del LLM.

## 1. Entorno

| Dato | Valor |
|---|---|
| Fecha de ejecución | 2026-10-26 |
| Host (SO / RAM / CPU) | macOS 26.5.2 · 16 GB · Apple M5 (10 núcleos) |
| Versión Docker / Compose | 29.3.1 / v5.1.1 |
| Modelo LLM (`LAB_MODELO`) | `llama3.2:3b` (Ollama, CPU) |
| Nº de corridas (n) | 3 (modo auto) + 1 con aprobación manual verificada |
| Modo de aprobación | auto (métricas) y manual (demo) |

## 2. Antes / después del bloqueo (evidencia de contención)

| Momento | Comando | Resultado |
|---|---|---|
| Antes | `nmap -p80 -Pn victima` | **`80/tcp open`** (el atacante alcanza la víctima) |
| Después | `nmap -p80 -Pn victima` | **`80/tcp filtered`** (contenido) |
| Tras rollback | `nmap -p80 -Pn victima` | **`80/tcp open`** (servicio restaurado) |

Regla aplicada por el firewall (de `output/firewall/estado.json`):
`-A INPUT -s 192.168.16.3/32 -j DROP`.

## 3. Métricas (n = 3)

| Métrica | Valor |
|---|---|
| **Tasa de contención** | **100 %** (3/3 verificadas por el firewall) |
| **Falsos positivos de respuesta** | **0** (siempre bloqueó la IP atacante real) |
| **Reversibilidad (rollback)** | **Sí** (regla eliminada, servicio restaurado) |
| **Automatización** | **100 %** (el agente ejecuta todo el flujo) |
| **Aprobación** | 1 acción con impacto → 1 aprobación (human-in-the-loop) |
| **Reproducibilidad** | **100 %** (contención estable en las 3 corridas) |
| **MTTR (corrida limpia)** | **124 s** (incluye carga en frío del modelo) |
| **Tiempo de proceso del agente (caliente)** | **~44 s** por corrida |

### Detalle por corrida

| Corrida | Aprobación | IP bloqueada | ¿Contenido? | MTTR (s) | Proceso agente (s) |
|---|---|---|---|---|---|
| 22:45:22Z | auto | 192.168.16.3 | sí | 124,4 | 157,5 (frío) |
| 22:49:07Z | auto | 192.168.16.3 | sí | 271,7* | 44,5 |
| 22:49:52Z | auto | 192.168.16.3 | sí | 315,3* | 43,5 |

\* **Nota metodológica (importante):** el MTTR se mide desde la **primera alerta
del incidente**, que es fija (el reconocimiento se ejecutó una sola vez). Al
repetir el agente sobre el *mismo* incidente almacenado, el MTTR se infla porque
crece el tiempo transcurrido desde esa primera alerta, no el trabajo del agente.
La medida representativa de un incidente real es la **corrida limpia (124 s)**, y
el **tiempo de proceso del agente** (~44 s en caliente) refleja su desempeño. Para
medir MTTR por corrida habría que **regenerar el incidente** (reset de `eve.json`
+ `recon_sim.py`) antes de cada respuesta.

## 4. Análisis

**Contención y tiempos**
- El agente bloqueó la IP atacante correcta en las 3 corridas (0 falsos
  positivos) y el firewall lo confirmó con la regla `iptables` activa.
- El antes/después lo demuestra empíricamente: `open → filtered → open`.
- MTTR de 124 s en frío; el cuello de botella es la **inferencia del LLM en CPU**
  (~44 s en caliente). Con GPU o un modelo servido en la nube bajaría a segundos.

**Decisión, aprobación y ejecución**
- La **separación agente/firewall** funcionó: el agente solo emitió órdenes; el
  firewall validó la IP y aplicó/revirtió la regla. El agente nunca tocó la red.
- La **compuerta de aprobación** se activó en cada bloqueo. En modo manual detiene
  la acción hasta la autorización; en auto queda registrado como aprobación
  automática (para métricas desatendidas).

**Seguridad y reversibilidad**
- El `--rollback` eliminó la regla y restauró el servicio sin residuos
  (`ips_bloqueadas: []`).
- Bloqueo **real pero contenido** en la red aislada; no se tocó nada externo.

**Límites y mejoras**
- Automatizar el bloqueo sin humano acelera el MTTR pero arriesga cortar tráfico
  legítimo: por eso la aprobación. Un siguiente paso sería una política de
  confianza (bloqueo automático solo para patrones de alta certeza).
- Para MTTR por corrida, regenerar el incidente antes de cada respuesta.

## 5. Evidencias

- `output/ordenes/ORD-*.json` — órdenes de bloqueo/desbloqueo con autorización y resultado.
- `output/firewall/estado.json` — reglas iptables activas.
- `output/trazas_respuesta/traza-*.jsonl` — razonamiento del agente.
- `output/informes_respuesta/informe-respuesta-*.md` — informes de respuesta.
- `output/metricas/run-*.json` y `resumen.json` — métricas.
- Capturas de los `nmap` antes/después/rollback.
