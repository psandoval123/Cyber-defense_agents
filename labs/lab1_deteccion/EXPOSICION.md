# Guion de exposición — Lab 1 (detección de reconocimiento con agente)

Guion práctico para presentar el laboratorio en vivo. Tiempos medidos en un
Apple M5 (CPU). **Prepara el entorno ANTES** (pasos 0) para no descargar nada
delante del público.

---

## 0. Antes de la exposición (una sola vez, con internet)

```bash
cd labs/lab1_deteccion
cp .env.example .env
docker compose up -d --build          # ~1-2 min la 1ª vez (build + imágenes)
docker compose exec ollama ollama pull llama3.2:3b   # ~2 GB, descarga lenta
```

Verifica que el modelo quedó disponible:

```bash
docker compose exec ollama ollama list   # debe listar llama3.2:3b
```

> Deja el stack levantado. Ya no necesitas internet para la demo (salvo que
> recrees el contenedor de Ollama).

**Corrida de calentamiento (justo antes de exponer).** El modelo se descarga de
la RAM tras un rato sin uso; la primera corrida "en frío" puede tardar 4-5 min.
Haz una corrida de prueba para dejarlo caliente y que la de la demo vaya a ~2 min:

```bash
docker compose exec atacante python3 recon_sim.py >/dev/null 2>&1
docker compose exec -T agente python3 agente_deteccion.py >/dev/null 2>&1
```

---

## 1. Discurso de apertura (1 min)

- **Problema:** el reconocimiento es la 1ª fase de un ataque (MITRE
  *Reconnaissance* / *Discovery*). Detectarlo temprano = reaccionar antes del
  impacto.
- **Propuesta:** un **agente de IA con LLM local** que lee las alertas del IDS,
  las clasifica, las mapea a ATT&CK y abre el caso/informe **solo, con
  trazabilidad**.
- **Montaje (enséñalo):** red Docker aislada, atacante → víctima, Suricata
  observando, y agente + Ollama en una red aparte.

```bash
docker compose ps        # los 5 servicios "Up"
```

## 2. Mostrar el aislamiento (30 s)

```bash
docker compose exec atacante nmap -p80 -Pn victima
docker compose exec atacante sh -c "getent hosts google.com && echo 'tiene internet' || echo 'OK: red aislada'"
```

> El atacante ve a la víctima, pero NO hay salida a internet: todo ocurre en un
> entorno controlado.

## 3. Lanzar el reconocimiento — el "ataque" (30 s + ~10 s de ejecución)

```bash
docker compose exec atacante python3 recon_sim.py
```

Verás en vivo: `nmap` (puertos/versiones), `whatweb` (nginx), `gobuster`
(rutas). Son las técnicas **T1046, T1592.002, T1595.003**.

## 4. Mostrar que el sensor lo vio (30 s)

```bash
# Total de alertas:
grep -c '"event_type":"alert"' output/suricata/eve.json

# Desglose por firma (cada una trae su técnica MITRE):
# OJO: el flag -T es obligatorio con heredoc (sin él: "input device is not a TTY").
docker compose exec -T agente python3 - <<'PY'
import json, collections
c=collections.Counter()
for l in open('/output/suricata/eve.json'):
    try: e=json.loads(l)
    except: continue
    if e.get('event_type')=='alert': c[e['alert']['signature']]+=1
for s,n in c.most_common(): print(f'{n:6}  {s}')
PY
```

> Miles de alertas en segundos. El sensor funciona; el reto es **interpretarlas**.

## 5. El agente entra en acción (⭐ el momento clave, ~2 min)

```bash
docker compose exec agente python3 agente_deteccion.py
```

Narra su ciclo **ReAct** mientras aparece en pantalla:
- 🧠 `consultar_alertas` → ve las firmas.
- 🧠 `enriquecer_attack` → confirma T1046 y T1595.003 contra MITRE.
- 🧠 `crear_caso` + `generar_informe` → documenta el incidente.
- ✓ **Veredicto: reconocimiento** y cierre automático en 5 pasos.

> Tarda ~2 min en CPU: aprovecha para explicar el razonamiento paso a paso.
> Si quieres evitar la espera en vivo, ten una corrida ya hecha y muestra el
> informe (paso 6) directamente.

## 6. Mostrar los entregables que generó (30 s)

> No pegues comentarios `# ...` en zsh: por defecto no los trata como comentario
> y `cat` intentará abrirlos como archivos. Usa los comandos limpios:

El caso (expediente del incidente):

```bash
cat output/casos/$(ls -t output/casos | head -1)
```

El informe final con recomendaciones:

```bash
cat output/informes/$(ls -t output/informes | head -1)
```

La traza del razonamiento del agente (evidencia de **trazabilidad**):

```bash
tail -n 20 output/trazas/$(ls -t output/trazas | head -1)
```

## 7. Las métricas (⭐ cierre con datos, 1 min)

```bash
python3 scripts/calcular_metricas.py
```

Resultados de referencia (n = 3):

| Métrica | Valor | Lectura |
|---|---|---|
| MTTD | 0,15 s | detección casi instantánea |
| Cobertura ATT&CK (sensor) | 100 % | el IDS vio las 3 técnicas |
| Precisión | 1,00 | 0 falsos positivos |
| Recall | 0,67 | el agente confirmó 2 de 3 |
| F1 | 0,80 | |
| Automatización | 100 % | sin intervención humana |
| Reproducibilidad | 100 % | veredicto estable en 3 corridas |

## 8. Preguntas frecuentes del jurado (prepárate)

- **¿Por qué recall 0,67 y no 1,0?** El fingerprinting (whatweb) genera **1 sola
  alerta** frente a miles del escaneo; el modelo pequeño prioriza el volumen.
  Mejora: pedirle enumerar todas las firmas distintas, o usar un modelo mayor.
- **¿Por qué un LLM local (Ollama)?** Privacidad de los datos de seguridad, sin
  coste por token y reproducibilidad offline (alineado con `skill_agentes.md`).
- **¿Se puede alucinar?** El agente solo usa técnicas de una base ATT&CK local
  (`attack_map.py`) y datos de las herramientas; en las pruebas: 0 alucinaciones.
- **¿Hace algo peligroso?** No: el Lab 1 solo observa, clasifica y documenta.
  La respuesta activa es el Lab 2.
- **¿Es reproducible?** Sí: todo es Docker; `docker compose up` + `pull` + los 3
  comandos. Temperatura 0 para estabilidad.

## 9. Reinicio limpio entre ensayos

```bash
# Borra evidencias previas para una demo limpia (conserva el modelo):
rm -rf output/casos output/informes output/metricas output/trazas output/atacante
: > output/suricata/eve.json 2>/dev/null || true
```

## 10. Apagar al terminar

```bash
docker compose down                 # detiene y elimina los contenedores
# docker compose down -v --rmi all  # además borra imágenes y el modelo
```
