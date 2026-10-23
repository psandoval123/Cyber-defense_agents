# Imagen del AGENTE DE DETECCIÓN para el Laboratorio 1.
# Python + cliente de Ollama. El agente razona sobre las alertas del sensor.
FROM python:3.12-slim

WORKDIR /agente

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "agente_deteccion.py"]
