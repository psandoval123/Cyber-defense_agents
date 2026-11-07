# Playbook: tráfico periódico BENIGNO (descartar falsos positivos)

## Por qué importa
No todo lo periódico es malicioso. Varios servicios legítimos generan conexiones
muy regulares —a veces **más regulares que un beacon**— y confundirlos con una
amenaza produce falsos positivos y bloqueos de servicio.

## Casos típicos de periodicidad legítima
- **NTP (sincronización horaria):** conexiones UDP al **puerto 123** hacia
  servidores de tiempo conocidos. Muy regulares, intervalo corto, benignas.
- **Actualizaciones de software:** sondeos periódicos a dominios de actualización
  reputados del fabricante.
- **Telemetría/healthchecks conocidos:** agentes de monitorización hacia destinos
  internos o del proveedor, documentados.

## Cómo distinguir benigno de C2
Pregúntate, para cada candidato periódico:
- ¿El **puerto/servicio** es uno estándar y esperado (123/NTP, etc.)?
- ¿El **destino** es un servidor conocido y reputado, o una IP/dominio sin reputación?
- ¿Hay un **dominio sospechoso** asociado, o ninguno/uno legítimo?
- ¿El comportamiento encaja con un servicio documentado de la organización?

**Regla práctica:** NTP al puerto 123 hacia un servidor de tiempo es **benigno**,
aunque su periodicidad sea altísima. Un canal ssl/443 sostenido hacia una IP
externa sin reputación y con dominio extraño es **sospechoso de C2**.

## Mapeo MITRE ATT&CK
No aplica: es actividad legítima. Documentarla reduce el ruido de futuras cacerías.
