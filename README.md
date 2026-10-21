# Cyber-defense_agents
Uso de Agentes Inteligentes en Ciberdefensa: Investigación, Diseño de Laboratorios para Detección y Respuesta a Incidentes de Seguridad

## Estructura del proyecto

| Carpeta | Contenido |
|---------|-----------|
| `agents/` | Agentes inteligentes: `triage_agent`, `hunting_agent`, `response_agent`. |
| `labs/` | Laboratorios reproducibles: `lab1_deteccion`, `lab2_respuesta`, `lab3_hunting`. |
| `infra/` | Infraestructura Docker (Wazuh, Suricata, Zeek, TheHive) y `docker-compose.base.yml`. |
| `docs/` | Contexto, estado del arte, arquitectura, metodología, cronograma, evaluación y ADRs. |
| `scripts/` | Utilidades, p. ej. `generate_synthetic_events.py` para generar eventos sintéticos. |
| `data/` | Datos sintéticos de prueba (sin datos sensibles). |
| `notebooks/` | Notebooks de análisis y evidencias. |
| `informe/` | Informe final del proyecto. |

## Principios

- Todo es reproducible con Docker.
- Solo se usan datos sintéticos; no se ejecutan ataques reales.
- Cada laboratorio incluye README, requisitos, pasos y métricas.
