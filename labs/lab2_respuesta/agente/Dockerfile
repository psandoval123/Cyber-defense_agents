# Imagen del AGENTE DE RESPUESTA para el Laboratorio 2.
FROM python:3.12-slim

WORKDIR /agente
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

CMD ["python", "response_agent.py"]
