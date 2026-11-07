# Playbook de caza: C2 Beaconing

## Qué es
El *beaconing* es el "latido" de una máquina comprometida que contacta a su
servidor de mando y control (C2) a intervalos regulares para pedir órdenes. Cada
conexión individual parece inocua, por lo que **evade las firmas de un IDS**: solo
el patrón temporal, repetido y regular, lo delata.

## Cómo cazarlo
- Agrupa las conexiones por par (origen, destino) y mide los intervalos entre
  conexiones. Un **coeficiente de variación (CV) bajo** (intervalos muy regulares)
  es la señal principal.
- Exige **persistencia**: muchas conexiones sostenidas durante una ventana larga.
- Señales de apoyo que elevan la sospecha:
  - Destino **externo** a la organización.
  - **Dominio sospechoso** o de aspecto generado (p. ej. "cdn-sync-telemetry").
  - Tamaños de datos pequeños y **constantes** (check-in sin payload).
  - Canal cifrado (ssl/tls) hacia una IP sin reputación.

## Cómo descartar falsos positivos
Mucho tráfico legítimo también es periódico (NTP, actualizaciones, telemetría).
Un intervalo regular **no basta**: confirma el destino, el puerto/servicio y la
reputación antes de concluir que es C2. Ver el playbook de tráfico periódico benigno.

## Mapeo MITRE ATT&CK
- **T1071.001** — Application Layer Protocol: Web Protocols (C2 sobre HTTP/S).
- **T1571** — Non-Standard Port.
- **T1008** — Fallback Channels.

## Respuesta recomendada
Aislar el host, bloquear el dominio/IP del C2 y revisar cómo se comprometió.
