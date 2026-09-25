# ADR-001: Docker Compose y datos sintéticos como base experimental

- Estado: Aceptado
- Fecha: 2026-09-24

## Contexto

El proyecto debe permitir laboratorios reproducibles de detección y respuesta sin utilizar ataques reales ni datos sensibles. Los servicios deben poder levantarse en un entorno controlado y sus resultados deben conservar evidencias verificables.

## Decisión

Usaremos Docker Compose como mecanismo base de despliegue y datos sintéticos o escenarios simulados como fuente de eventos para los laboratorios iniciales.

La infraestructura utilizará redes internas aisladas, variables de entorno y healthchecks. Las acciones de respuesta con posible impacto se representarán inicialmente como simulaciones trazables.

## Consecuencias

### Positivas

- Despliegue repetible en un entorno local.
- Separación clara entre servicios y laboratorios.
- Menor riesgo al trabajar con datos controlados.
- Facilidad para conservar configuraciones y evidencias.

### Negativas

- El entorno puede requerir recursos considerables.
- Los resultados no representan automáticamente un entorno productivo.
- Algunos comportamientos reales deberán aproximarse mediante simulaciones.

## Revisión

Esta decisión se revisará cuando exista una primera composición funcional y se conozcan sus requisitos de CPU, memoria, almacenamiento y compatibilidad con el entorno local.
