# Agente de hunting

El agente de hunting (lado defensivo) **busca proactivamente** amenazas que
evaden las firmas: formula hipótesis, consulta una base de conocimiento (RAG),
analiza los datos, refina con más fuentes y emite un veredicto fundamentado.

Su **primera implementación ejecutable** vive en el Laboratorio 3:

- Código: [`labs/lab3_hunting/agente/`](../../labs/lab3_hunting/agente/)
- Interfaz: [`labs/lab3_hunting/ui/app.py`](../../labs/lab3_hunting/ui/app.py)
- Diseño y guía: [`labs/lab3_hunting/DISENO.md`](../../labs/lab3_hunting/DISENO.md) ·
  [`labs/lab3_hunting/README.md`](../../labs/lab3_hunting/README.md)

Allí el agente caza un **C2 beaconing** oculto usando un grafo **LangGraph**
(razonamiento multi-paso con ciclo de refinamiento), **RAG** con Chroma y
embeddings locales, y un dashboard **Streamlit**.
