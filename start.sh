#!/bin/bash
# start.sh
# Inicia el entorno de escritorio virtual (Xvfb + Fluxbox + x11vnc + noVNC)
# y luego arranca la aplicación de Streamlit.

# 1. Iniciar Xvfb (Virtual Framebuffer)
# Crea un display virtual en el puerto :0 con resolucion 1920x1080
export DISPLAY=:0
Xvfb :0 -screen 0 1920x1080x24 -listen tcp -ac &
XVFB_PID=$!
echo "[start.sh] Xvfb iniciado (PID: $XVFB_PID)"

# Esperar un momento a que Xvfb este listo
sleep 2

# 2. Iniciar Fluxbox (Gestor de ventanas muy ligero)
fluxbox -display :0 &
FLUXBOX_PID=$!
echo "[start.sh] Fluxbox iniciado (PID: $FLUXBOX_PID)"

# 3. Iniciar x11vnc (Servidor VNC)
# Se enlaza al display :0, sin password
x11vnc -display :0 -nopw -listen 127.0.0.1 -xkb -forever -shared &
VNC_PID=$!
echo "[start.sh] x11vnc iniciado (PID: $VNC_PID)"

# 4. Iniciar websockify (Puente WebSockets para noVNC)
# noVNC suele estar instalado en /usr/share/novnc en Debian/Ubuntu
websockify --web=/usr/share/novnc/ --wrap-mode=ignore 8080 127.0.0.1:5900 &
WEBSOCKIFY_PID=$!
echo "[start.sh] websockify iniciado en puerto 8080 (PID: $WEBSOCKIFY_PID)"

# 5. Iniciar la aplicación principal de Streamlit
echo "[start.sh] Iniciando Streamlit..."
streamlit run app_gui.py --server.port=8501 --server.address=0.0.0.0
