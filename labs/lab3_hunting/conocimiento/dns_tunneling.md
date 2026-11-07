# Playbook de caza: DNS Tunneling / exfiltración por DNS

## Qué es
Técnica que abusa del protocolo DNS para encapsular datos o un canal de C2,
aprovechando que el tráfico DNS casi nunca se bloquea ni se inspecciona a fondo.

## Cómo cazarlo
- **Volumen anómalo** de consultas DNS desde un host hacia un mismo dominio base.
- **Nombres largos** y de alta **entropía** (subdominios aleatorios), muy distintos
  de los dominios legibles habituales.
- Predominio de tipos de registro poco comunes (TXT, NULL) o muchas respuestas
  que no resuelven a direcciones normales.

## Cómo descartar falsos positivos
CDNs y antivirus/telemetría generan muchas consultas legítimas. Fíjate en la
entropía y la longitud de los subdominios, no solo en el volumen.

## Mapeo MITRE ATT&CK
- **T1071.004** — Application Layer Protocol: DNS.
- **T1048** — Exfiltration Over Alternative Protocol.
