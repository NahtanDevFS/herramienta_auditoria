# Herramienta de Auditoría de Seguridad Web (OWASP Top 10)

Herramienta de auditoría de seguridad web que combina módulos de escaneo
automático (cabeceras HTTP, cookies, TLS/SSL, puertos, nmap, sqlmap, nuclei,
crawler y más) con un **agente de pentesting basado en un modelo de lenguaje
local**. Los módulos generan un reporte preliminar de posibles vulnerabilidades
y, a partir de él, el agente decide sobre cuáles profundizar y ejecuta pruebas
activas dentro de límites de seguridad estrictos. El resultado es un reporte de
hallazgos (HTML/PDF) mapeado al OWASP Top 10. Todo corre en local, sin APIs de
pago ni claves en la nube.

> **Uso ético y legal.** Solo debes auditar sistemas propios o para los que
> tengas autorización explícita. La herramienta no se ejecuta si
> `autorizacion_confirmada` no está en `true`. Para practicar legalmente usa
> laboratorios como **OWASP Juice Shop**, **DVWA** o **WebGoat**.

---

## Requisitos

- **Ollama** — para correr el modelo de IA local. Descárgalo en https://ollama.com
- **Python 3.12+** — para la instalación manual.
- **Docker + Docker Compose** — para la instalación con Docker (opción rápida).
- Herramientas de sistema según los módulos que actives: `nmap`, `sqlmap`,
  `nuclei`. (Opcionales; los módulos que no tengan su herramienta se saltan.)

> El modelo de IA (`jonathanFS/pentest-owasp`, ~4.7 GB) se descarga con Ollama;
> no está incluido en el repositorio.

---

## Instalación

### Opción A — Docker (recomendada)

Ejecuta la herramienta con todas sus dependencias (Nmap, ZAP, SQLmap, Playwright, etc.) en un contenedor aislado, usando tu instalación local de Ollama.

```bash
# 1) Clona el repositorio
git clone https://github.com/NahtanDevFS/herramienta_auditoria.git
cd herramienta_auditoria

# 2) Ollama en tu máquina, escuchando en TODAS las interfaces (para que el
#    contenedor pueda alcanzarlo), y descarga el modelo:
#    - Windows (una sola vez, luego reabre Ollama):  setx OLLAMA_HOST "0.0.0.0"
#    - Mac / Linux:                                   OLLAMA_HOST=0.0.0.0 ollama serve
ollama pull jonathanFS/pentest-owasp

# 3) Construye la imagen de la herramienta (solo la primera vez)
docker build -t auditoria_web .

# 4) Levanta la interfaz gráfica y el monitor en vivo.
#    --add-host hace que host.docker.internal también funcione en Linux (en Docker
#    Desktop de Windows/Mac ya funciona solo, y el flag no estorba).
docker run --rm -it \
  -p 8501:8501 \
  -p 8080:8080 \
  --add-host=host.docker.internal:host-gateway \
  -e OLLAMA_HOST=http://host.docker.internal:11434 \
  auditoria_web
```

> **Único requisito de red:** Ollama debe escuchar en `0.0.0.0` (paso 2). Por
> defecto solo escucha en `127.0.0.1` y el contenedor no lo alcanza. Es un ajuste
> de una sola vez. El resto (frontend, backend, base de datos que auditas) se
> queda tal cual: la herramienta nunca toca tu base de datos directamente.

La interfaz gráfica estará disponible en **http://localhost:8501** y el monitor en vivo del navegador en **http://localhost:8080/vnc.html**.

### Opción B — Instalación Manual (sin Docker)

```bash
# 1) Clona el repositorio
git clone https://github.com/NahtanDevFS/herramienta_auditoria.git
cd herramienta_auditoria

# 2) Instala Ollama (https://ollama.com) y descarga el modelo
ollama pull jonathanFS/pentest-owasp

# 3) Crea el entorno de Python e instala dependencias
python3 -m venv venv
source venv/bin/activate          # En Windows: venv\Scripts\activate
pip install -r requirements.txt

# 4) Instala las herramientas de navegador para Playwright
playwright install chromium
playwright install-deps

# 5) Instala las herramientas de sistema (Debian/Ubuntu)
sudo apt install nmap sqlmap default-jre \
                 libpango-1.0-0 libpangoft2-1.0-0 libcairo2 \
                 libgdk-pixbuf-2.0-0 shared-mime-info
#   Nota: ZAP y Nuclei deben instalarse manualmente en esta opción.

# 6) Inicia la herramienta
streamlit run app_gui.py
```

---

## Uso

### 1. Levanta un objetivo de práctica (opcional)

Si no tienes un sitio propio para auditar, puedes usar OWASP Juice Shop:

```bash
docker run --rm -p 3000:3000 bkimminich/juice-shop
```

### 2. Abre la interfaz web

Una vez que el contenedor de la herramienta esté corriendo, abre tu navegador y ve a:

```
http://localhost:8501
```

### 3. Configura la auditoría desde la barra lateral

En el panel izquierdo de la interfaz encontrarás:

| Campo | Qué poner |
|-------|-----------|
| **URL objetivo** | La dirección del sitio a auditar. Si usas Docker, recuerda usar `http://host.docker.internal:3000` en lugar de `http://localhost:3000`, ya que `localhost` dentro del contenedor apunta a sí mismo. |
| **Nombre del proyecto** | Un nombre descriptivo para identificar el reporte. |
| **Módulos** | Activa o desactiva los escáneres que quieras ejecutar (cabeceras, cookies, nmap, ZAP, crawler, agente IA, etc.). |
| **Agente de IA** | Si lo activas, configura el modelo (`jonathanFS/pentest-owasp`), el host de Ollama y las credenciales opcionales para auditar zonas autenticadas. |
| **Monitor en vivo** | Marca "Mostrar navegador visualmente" para ver en tiempo real cómo el agente de IA interactúa con el sitio desde un escritorio virtual integrado. |
| **Autorización** | Marca la casilla confirmando que tienes permiso para auditar el objetivo. |

### 4. Inicia la auditoría

Pulsa el botón **"Iniciar auditoría"**. Verás:

1. Una **barra de progreso** con el módulo que se está ejecutando.
2. Una **terminal de logs** con los mensajes en tiempo real.
3. El **monitor en vivo** (desplegable) donde puedes observar al agente de IA navegando, haciendo clics e inyectando pruebas directamente en el sitio.

### 5. Revisa los resultados

Al finalizar, la interfaz mostrará:

- **Resumen de riesgo global** con puntuación de 0 a 10.
- **Tabla de hallazgos** clasificados por severidad y categoría OWASP.
- **Botones de descarga** para el reporte en formato HTML y PDF.
- **Video de la sesión** del agente de IA (si usó el navegador).

Los reportes también quedan guardados en la carpeta `resultados/` del proyecto.

> Para tu primera corrida, usa `limite_acciones` bajo (5–8): la sesión es más
> corta y puedes revisar con calma en los logs qué hizo el agente.