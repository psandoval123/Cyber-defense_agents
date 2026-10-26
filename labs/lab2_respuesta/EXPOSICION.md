# Guion de exposición — Lab 2 (respuesta/contención con agente)

Guion para presentar el Lab 2 en vivo. Preséntalo **después** del Lab 1 (la
narrativa es "detectar → responder"). Prepara el entorno ANTES (paso 0).

---

## 0. Antes de la exposición (una sola vez, con internet)

```bash
cd labs/lab2_respuesta
cp .env.example .env
docker compose up -d --build
docker compose exec ollama ollama pull llama3.2:3b   # o reutiliza el del Lab 1 (ver README)
```

**Corrida de calentamiento** (deja el modelo en RAM y verifica el flujo):

```bash
docker compose exec atacante python3 recon_sim.py >/dev/null 2>&1
LAB_AUTO_APROBAR=true docker compose exec -e LAB_AUTO_APROBAR=true response_agent python3 response_agent.py >/dev/null 2>&1
docker compose exec response_agent python3 response_agent.py --rollback   # revierte el calentamiento
```

> Deja el stack levantado. Ya no necesitas internet.

---

## 1. Discurso de apertura (1 min)

- **Hilo con el Lab 1:** "ya detectamos el reconocimiento; ahora el agente lo
  **contiene**".
- **Dos ideas clave que vas a demostrar:**
  1. **Separación decisión/ejecución:** el agente decide y ordena; un firewall
     aparte aplica. El agente no tiene privilegios de red.
  2. **Humano en el bucle:** la acción con impacto (bloquear) **requiere tu
     aprobación**.

```bash
docker compose ps        # 6 servicios Up (incluye firewall)
```

## 2. El atacante ataca y, de momento, entra (30 s)

```bash
docker compose exec atacante python3 recon_sim.py
docker compose exec atacante nmap -p80 -Pn victima   # 80/tcp OPEN -> alcanza a la víctima
```

> Señala el `80/tcp open`: el atacante llega a la víctima. Hay que cortarlo.

## 3. El agente responde (⭐ el momento clave, ~2 min)

```bash
docker compose exec response_agent python3 response_agent.py
```

Narra mientras aparece:
- 🧠 `consultar_incidente` → identifica la **IP atacante** desde las alertas.
- 🧠 propone bloquearla → **se detiene y te pide aprobación**. Escribe `s` y Enter.
  *(Este es el punto pedagógico: una IA autónoma, pero con control humano.)*
- ⚙️ `bloquear_ip` → emite la orden; el **firewall** aplica el `iptables DROP`.
- 🧠 `verificar_contencion` → el firewall confirma la regla activa.
- ⚙️ `generar_informe_respuesta` → informe con **MTTR**.

## 4. La prueba: el atacante ya NO entra (⭐ 30 s)

```bash
docker compose exec atacante nmap -p80 -Pn victima   # ahora 80/tcp FILTERED
```

> El mismo comando que antes daba `open` ahora da `filtered`. **Contención
> demostrada**, y todo dentro del laboratorio aislado.

## 5. Entregables y trazabilidad (30 s)

```bash
cat output/ordenes/$(ls -t output/ordenes | head -1)                       # la orden, con autorización y resultado
cat output/informes_respuesta/$(ls -t output/informes_respuesta | head -1) # el informe con MTTR
cat output/firewall/estado.json                                            # reglas iptables activas
```

## 6. Las métricas (cierre con datos, 1 min)

```bash
python3 scripts/calcular_metricas.py
```

Explica: **MTTR** (qué tan rápido se contuvo), **tasa de contención**,
**falsos positivos de respuesta** (0 = no bloqueó a nadie legítimo),
**aprobación** (hubo intervención humana) y **reversibilidad**.

## 7. Reversibilidad (deja el entorno limpio, 15 s)

```bash
docker compose exec response_agent python3 response_agent.py --rollback
docker compose exec atacante nmap -p80 -Pn victima   # vuelve a 80/tcp open
```

## 8. Preguntas probables del jurado

- **¿El bloqueo es real?** Sí, es `iptables` de verdad, pero dentro de la red
  Docker aislada del laboratorio y **reversible**. No toca nada externo.
- **¿Por qué pedir aprobación?** Porque bloquear es una acción con impacto;
  automatizarla a ciegas puede cortar servicio legítimo. El humano decide; el
  agente prepara y ejecuta. (Lo pide tu propia arquitectura.)
- **¿Por qué el agente no aplica el iptables directamente?** Separación de
  responsabilidades y mínimo privilegio: el agente solo emite una orden que el
  firewall valida y aplica. Más seguro y auditable.
- **¿Qué pasa si el modelo se equivoca de IP?** El firewall valida el formato y
  queda la traza; además la métrica "falsos positivos de respuesta" lo mediría.
- **¿Escala a bloqueos reales en producción?** Sí, cambiando el enforcer por uno
  que hable con el firewall real; el diseño (decisión/ejecución/aprobación) no
  cambia.

## 9. Reinicio limpio entre ensayos

```bash
docker compose exec response_agent python3 response_agent.py --rollback
rm -rf output/ordenes output/informes_respuesta output/metricas output/trazas_respuesta
: > output/suricata/eve.json 2>/dev/null || true
```

## 10. Apagar

```bash
docker compose down
```
