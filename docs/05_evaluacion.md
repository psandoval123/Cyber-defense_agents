# Plan de evaluación

## Métricas obligatorias

- **MTTD:** tiempo medio desde la generación del evento hasta su detección.
- **MTTR:** tiempo medio desde la detección hasta la respuesta definida para el escenario.
- **Precisión:** proporción de detecciones clasificadas correctamente entre todas las detecciones positivas.
- **Recall:** proporción de eventos positivos detectados.
- **F1:** media armónica de precisión y recall.
- **Falsos positivos:** alertas clasificadas como incidentes cuando no corresponden a un evento positivo.
- **Cobertura MITRE ATT&CK:** técnicas representadas y detectadas dentro del alcance del laboratorio.
- **Nivel de automatización:** proporción de pasos ejecutados por el agente sin intervención manual, siempre con trazabilidad.
- **Reproducibilidad:** capacidad de repetir el despliegue y obtener evidencias equivalentes.

## Reglas de medición

1. Cada escenario tendrá datos sintéticos conocidos y una expectativa explícita.
2. Los tiempos se tomarán de logs con marcas temporales.
3. Las métricas se calcularán a partir de evidencias almacenadas en el repositorio.
4. No se publicarán resultados hasta ejecutar y verificar el escenario.
5. Las limitaciones y casos no medidos quedarán registrados junto con los resultados.

## Evidencias esperadas

- Logs de despliegue y ejecución.
- Configuraciones utilizadas.
- Scripts o notebooks de cálculo.
- Capturas de las interfaces cuando aporten evidencia.
- Tabla final de resultados por laboratorio.
