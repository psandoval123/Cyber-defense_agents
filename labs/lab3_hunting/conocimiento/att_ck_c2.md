# Fichas MITRE ATT&CK — Command and Control (TA0011)

## T1071.001 — Application Layer Protocol: Web Protocols
C2 que viaja sobre HTTP/HTTPS para mezclarse con el tráfico web normal. El
beaconing regular a un servidor web externo es su manifestación típica.

## T1571 — Non-Standard Port
Uso de puertos no estándar (o de un puerto estándar para un fin no estándar, como
SSL/443 sostenido hacia una IP sin reputación) para el canal de C2.

## T1008 — Fallback Channels
Canales de respaldo que el malware usa si el C2 primario falla; refuerza la
persistencia del beaconing.

## T1071.004 — Application Layer Protocol: DNS
C2 o exfiltración encapsulados en consultas DNS.

## Cómo se relacionan con la caza
Un patrón de beaconing (intervalos regulares, destino externo, dominio sospechoso)
se mapea principalmente a **T1071.001** y, si usa un puerto/propósito no estándar,
a **T1571**. Documentar la técnica da contexto y guía la respuesta.
