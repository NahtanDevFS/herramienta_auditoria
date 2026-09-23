# Usa una imagen oficial de Python ligera
FROM python:3.12-slim

# Evita que apt-get haga preguntas interactivas
ENV DEBIAN_FRONTEND=noninteractive

# 1. Instalar herramientas del sistema y dependencias de terceros
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    curl \
    unzip \
    nmap \
    sqlmap \
    default-jre \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

# 2. Instalar Nuclei (Binario independiente)
RUN wget https://github.com/projectdiscovery/nuclei/releases/download/v3.3.0/nuclei_3.3.0_linux_amd64.zip -O nuclei.zip \
    && unzip nuclei.zip -d /usr/local/bin/ \
    && rm nuclei.zip \
    && chmod +x /usr/local/bin/nuclei

# 3. Instalar OWASP ZAP (Cross Platform)
RUN wget https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2.17.0_Crossplatform.zip -O zap.zip \
    && unzip zap.zip -d /opt/ \
    && rm zap.zip \
    && ln -s /opt/ZAP_2.17.0/zap.sh /usr/local/bin/zap.sh

# 4. Configurar el directorio de trabajo
WORKDIR /app

# 5. Instalar dependencias de Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 6. Instalar Playwright (Navegador Chromium)
RUN playwright install chromium
RUN playwright install-deps

# 7. Copiar el código fuente
COPY . .

# 8. Exponer el puerto de Streamlit
EXPOSE 8501

# 9. Comando por defecto: Lanzar la GUI
CMD ["streamlit", "run", "app_gui.py", "--server.port=8501", "--server.address=0.0.0.0"]
