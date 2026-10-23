# Agente de triage

El agente de triage (lado defensivo) razona sobre alertas de los sensores,
las clasifica, las enriquece con MITRE ATT&CK y abre casos/informes.

Su **primera implementación ejecutable** vive en el Laboratorio 1:

- Código: [`labs/lab1_deteccion/agente/`](../../labs/lab1_deteccion/agente/)
- Guía y ejecución: [`labs/lab1_deteccion/README.md`](../../labs/lab1_deteccion/README.md)

Allí el agente detecta **reconocimiento automatizado** (patrón ReAct sobre un
LLM local con Ollama). En labs posteriores se extiende a respuesta y hunting.
