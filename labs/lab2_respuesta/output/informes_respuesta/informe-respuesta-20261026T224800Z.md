# Informe de respuesta — Contenido del incidente de reconocimiento

- **Fecha:** 2026-10-26T22:48:00.331594+00:00
- **IP contenida:** 192.168.16.3
- **Acción:** Bloqueo de IP
- **Autorización:** Aprobada por el equipo de seguridad
- **Resultado:** Éxito
- **MTTR:** 10 s
- **Generado por:** agente de respuesta (Lab 2, LLM local)

## Resumen

La IP 192.168.16.3 ha sido bloqueada con éxito, evitando el reconocimiento de ataque.

## Técnicas MITRE ATT&CK del incidente

- `T1046`
- `T1592.002`
- `T1595.003`

## Reversibilidad

El bloqueo es reversible: `docker compose exec response_agent python3 response_agent.py --rollback` o eliminando la regla en el firewall. Queda registrado en `output/ordenes/`.
