# Imagen del FIREWALL (enforcer) para el Laboratorio 2.
# Aplica/revierte reglas iptables en el namespace de red de la víctima.
# Es el "músculo" que EJECUTA lo que el agente DECIDE (separación de roles).
FROM alpine:3.20

# iptables para aplicar los bloqueos; python3 para el bucle del enforcer.
RUN apk add --no-cache iptables python3

WORKDIR /firewall
COPY enforcer.py .

# Proceso principal del contenedor: vigila órdenes y las aplica.
CMD ["python3", "enforcer.py"]
