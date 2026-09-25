# Infraestructura

## Requisito local

Docker Desktop debe estar iniciado y el daemon debe responder antes de ejecutar los comandos de despliegue.

## Estado actual

La primera composición valida el ciclo mínimo de infraestructura: Docker Compose, red interna aislada, volumen de evidencias y generación de telemetría sintética.

## Arranque

Desde la raíz del repositorio:

```bash
docker compose -f infra/docker-compose.base.yml up -d
```

## Verificación

```bash
docker compose -f infra/docker-compose.base.yml ps
cat data/events.jsonl
cat data/heartbeat
```

## Detención

```bash
docker compose -f infra/docker-compose.base.yml down
```

## Servicios previstos posteriormente

- Sensores: Suricata, Zeek y Wazuh.
- Almacenamiento y consulta de eventos.
- Gestión de casos con TheHive.
- Componentes de agentes y herramientas controladas.

Estos servicios se incorporarán después de validar esta base y documentar sus requisitos de recursos, puertos, credenciales de desarrollo y healthchecks.
