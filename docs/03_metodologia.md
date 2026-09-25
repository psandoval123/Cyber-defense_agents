# Metodología

## Enfoque

Se utilizará un enfoque experimental incremental. Cada laboratorio tendrá un escenario controlado, una expectativa conocida, una ejecución reproducible y una evaluación basada en evidencias.

## Fases

### 1. Preparación

- Definir el objetivo y el alcance del escenario.
- Identificar la técnica o comportamiento simulado.
- Preparar datos sintéticos y configuraciones versionadas.
- Definir la evidencia mínima y las métricas.

### 2. Despliegue

- Levantar los servicios mediante `docker compose up -d`.
- Verificar healthchecks y conectividad interna.
- Registrar versiones, configuración y puertos utilizados.

### 3. Ejecución

- Ejecutar únicamente el guion simulado documentado.
- Capturar timestamps de generación, detección y respuesta.
- Registrar las entradas y salidas de cada herramienta del agente.

### 4. Evaluación

- Comparar alertas y resultados con la expectativa del escenario.
- Calcular MTTD, MTTR, precisión, recall, F1 y falsos positivos cuando aplique.
- Medir cobertura ATT&CK, automatización y reproducibilidad.
- Registrar fallos, decisiones ambiguas y límites del experimento.

### 5. Repetición

- Repetir el escenario con la misma configuración.
- Comparar evidencias y métricas.
- Investigar cualquier diferencia antes de consolidar resultados.

## Diseño de agentes

Los agentes se diseñarán con tareas acotadas y herramientas explícitas:

- **Triage:** priorizar y resumir alertas con referencias a eventos fuente.
- **Respuesta:** proponer o ejecutar respuestas simuladas con autorización y registro.
- **Hunting:** formular hipótesis, consultar eventos y devolver evidencias.

Cada agente deberá registrar:

1. Identificador del caso o ejecución.
2. Entrada recibida.
3. Herramientas invocadas y parámetros no sensibles.
4. Resultado de cada herramienta.
5. Decisión o recomendación.
6. Evidencia utilizada.
7. Errores, incertidumbre y necesidad de revisión humana.

## Control de alucinaciones

- Las afirmaciones deberán enlazar con eventos, documentos o resultados de herramientas.
- Las fuentes recuperadas se conservarán junto con el resultado.
- Las respuestas sin evidencia suficiente se marcarán como inciertas.
- Se evaluarán casos positivos, negativos y ambiguos.

## Criterio de finalización de un laboratorio

Un laboratorio se considerará completo cuando tenga README, despliegue reproducible, escenario simulado, agente documentado, métricas calculadas, evidencias almacenadas, preguntas de reflexión y lecciones aprendidas.
