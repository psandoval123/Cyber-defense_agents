# Agente de respuesta

El agente de respuesta (lado defensivo) toma un incidente, decide una acción de
contención, la somete a **aprobación humana** y la ejecuta de forma reversible y
trazable, separando la **decisión** (agente) de la **ejecución** (firewall).

Su **primera implementación ejecutable** vive en el Laboratorio 2:

- Código: [`labs/lab2_respuesta/agente/`](../../labs/lab2_respuesta/agente/)
- Firewall (ejecución): [`labs/lab2_respuesta/firewall/`](../../labs/lab2_respuesta/firewall/)
- Guía y ejecución: [`labs/lab2_respuesta/README.md`](../../labs/lab2_respuesta/README.md)

Allí el agente contiene un **reconocimiento** (el del Lab 1) bloqueando la IP
atacante con `iptables`, dentro de una red Docker aislada y con `--rollback`.
