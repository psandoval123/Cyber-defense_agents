# Imagen del ADVERSARIO EMULADO para el Laboratorio 1 (detección).
# Su único fin es generar tráfico de reconocimiento REALISTA y REPRODUCIBLE
# contra la víctima del laboratorio, para que el sensor y el agente lo detecten.
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# Herramientas de reconocimiento (solo lectura; no modifican el objetivo):
#   nmap     -> descubrimiento de puertos y versiones (T1046)
#   whatweb  -> fingerprinting de tecnologías web (T1592.002)
#   gobuster -> enumeración de rutas web (T1595.003)
#   dirb     -> se instala solo por su diccionario (common.txt) para gobuster
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        whatweb \
        gobuster \
        dirb \
        python3 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /atacante
COPY recon_sim.py .

CMD ["python3", "recon_sim.py"]
