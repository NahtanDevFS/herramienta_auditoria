# =============================================================================
# Dockerfile — herramienta de auditoria de seguridad web
# Empaqueta la app + las herramientas de sistema para que "cualquiera" pueda
# levantarla sin instalar dependencias a mano.
# =============================================================================
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# --- Dependencias de sistema -------------------------------------------------
# - nmap, sqlmap: herramientas de escaneo (via apt).
# - libpango/cairo/gdk-pixbuf: necesarias para que WeasyPrint genere el PDF.
# - curl/unzip/ca-certificates: para descargar nuclei.
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        sqlmap \
        curl \
        unzip \
        ca-certificates \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        libharfbuzz0b \
        libcairo2 \
        libgdk-pixbuf-2.0-0 \
        libffi-dev \
        shared-mime-info \
        fonts-dejavu \
    && rm -rf /var/lib/apt/lists/*

# --- nuclei (opcional) -------------------------------------------------------
# Debian no lo empaqueta; se baja el binario. Si falla, la imagen igual se
# construye y el modulo 'nuclei' simplemente se salta si no esta activo.
ARG NUCLEI_VERSION=3.3.7
RUN curl -sL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -o /tmp/nuclei.zip \
    && unzip -o /tmp/nuclei.zip -d /usr/local/bin/ \
    && rm -f /tmp/nuclei.zip \
    || echo "AVISO: no se pudo instalar nuclei; deja modulos.nuclei en false o instalalo aparte."

WORKDIR /app

# --- Dependencias de Python --------------------------------------------------
COPY requirements.txt .
# 'ollama' y 'python-dotenv' se aseguran aqui por si no estan en requirements.
RUN pip install -r requirements.txt \
    && pip install ollama python-dotenv

COPY . .

# Streamlit
EXPOSE 8501
CMD ["streamlit", "run", "app_gui.py", \
     "--server.address=0.0.0.0", "--server.port=8501"]