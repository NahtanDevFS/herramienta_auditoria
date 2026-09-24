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

## ¿Qué puedes auditar?

Cualquier sitio web al que tengas autorización, esté publicado en internet o
corriendo en tu propia máquina:

- **Sitios públicos (ya publicados en internet):** solo pon la URL completa (por
  ejemplo `https://midominio.com`) y listo. No necesitas configurar nada de red.
- **Apps en tu propia máquina (localhost):** como la herramienta corre dentro de
  Docker, `localhost` apunta al contenedor, no a tu PC. Usa
  `http://host.docker.internal:PUERTO` como objetivo. Si además auditas la zona
  autenticada, permite ese origen en el CORS de tu backend.

---

## Requisitos

Común a cualquier instalación:

- **Ollama:** para correr el modelo de IA local. Descárgalo en https://ollama.com

Si usas **Docker (Opción A, recomendada)**, no necesitas nada más. Nmap, SQLmap,
Nuclei, ZAP y Playwright ya vienen preinstalados dentro de la imagen.

- **Docker Desktop:** https://www.docker.com/products/docker-desktop/

Si usas la **instalación manual (Opción B)**, necesitas además:

- **Python 3.12+**
- Herramientas de sistema según los módulos que actives: `nmap`, `sqlmap`,
  `nuclei` (opcionales: los módulos que no tengan su herramienta se saltan).

> El modelo de IA (`jonathanFS/pentest-owasp`, ~4.7 GB) se descarga con Ollama.
> No está incluido en el repositorio.

---

## Instalación

### Opción A: Docker (recomendada)

Ejecuta la herramienta con todas sus dependencias (Nmap, ZAP, SQLmap, Playwright,
etc.) en un contenedor aislado, usando tu instalación local de Ollama.

**Requisitos previos:** tener instalados
[Docker Desktop](https://www.docker.com/products/docker-desktop/) y
[Ollama](https://ollama.com), y ambos abiertos.

Sigue los pasos **en orden**. Todos los comandos se pegan en una terminal:

- **En Windows:** abre **PowerShell** (menú Inicio, escribe `PowerShell`, Enter).
- **En Mac/Linux:** abre la **Terminal**.

Pega **cada comando completo** en una sola línea, no lo partas.

#### 1. Clona el repositorio y entra a la carpeta

```bash
git clone https://github.com/NahtanDevFS/herramienta_auditoria.git
```

```bash
cd herramienta_auditoria
```

#### 2. Deja que el contenedor pueda usar tu Ollama (se hace UNA sola vez)

Por defecto Ollama solo acepta conexiones locales, así que el contenedor no lo
alcanza. Hay que decirle que escuche en todas las interfaces.

**Windows:** pega esto en PowerShell.

```powershell
setx OLLAMA_HOST "0.0.0.0"
```

Después **cierra Ollama por completo**: clic derecho en su icono de la bandeja
del sistema (abajo a la derecha, junto al reloj, puede estar en la flecha `∧`) y
elige **Quit Ollama**. Luego **ábrelo otra vez** desde el menú Inicio.

**Mac/Linux:** cierra Ollama y arráncalo así en la Terminal.

```bash
OLLAMA_HOST=0.0.0.0 ollama serve
```

#### 3. Descarga el modelo de IA

```bash
ollama pull jonathanFS/pentest-owasp
```

#### 4. Construye la imagen (solo la primera vez, tarda varios minutos)

```bash
docker build -t auditoria_web .
```

#### 5. Levanta la herramienta

Pega esta línea **completa, tal cual, en una sola línea** (funciona igual en
PowerShell, CMD y Terminal).

```bash
docker run --rm -it -p 8501:8501 -p 8080:8080 --add-host=host.docker.internal:host-gateway -e OLLAMA_HOST=http://host.docker.internal:11434 auditoria_web
```

#### 6. Abre la herramienta en tu navegador

- **Interfaz gráfica:** http://localhost:8501
- **Monitor en vivo del navegador:** http://localhost:8080/vnc.html

Para detenerla, vuelve a la terminal donde corre y pulsa `Ctrl + C`.

> **Nota:** el único ajuste de red es el del paso 2 (Ollama en `0.0.0.0`): se hace
> una vez y no se repite. El resto de tu sistema (frontend, backend y la base de
> datos que auditas) se queda tal cual, la herramienta nunca toca tu base de datos
> directamente.

### Opción B: instalación manual (sin Docker)

Sigue los pasos **en orden**, cada comando en una sola línea.

#### 1. Clona el repositorio y entra a la carpeta

```bash
git clone https://github.com/NahtanDevFS/herramienta_auditoria.git
```

```bash
cd herramienta_auditoria
```

#### 2. Instala Ollama y descarga el modelo

Instala Ollama desde https://ollama.com y luego descarga el modelo.

```bash
ollama pull jonathanFS/pentest-owasp
```

#### 3. Crea el entorno de Python e instala dependencias

```bash
python3 -m venv venv
```

```bash
source venv/bin/activate
```

En Windows, en lugar del comando anterior usa `venv\Scripts\activate`.

```bash
pip install -r requirements.txt
```

#### 4. Instala los navegadores de Playwright

```bash
playwright install chromium
```

```bash
playwright install-deps
```

#### 5. Instala las herramientas de sistema (Debian/Ubuntu)

```bash
sudo apt install nmap sqlmap default-jre libpango-1.0-0 libpangoft2-1.0-0 libcairo2 libgdk-pixbuf-2.0-0 shared-mime-info
```

ZAP y Nuclei se instalan aparte de forma manual en esta opción.

#### 6. Inicia la herramienta

```bash
streamlit run app_gui.py
```

---

## Uso

### 1. Levanta un objetivo de práctica (opcional)

Si no tienes un sitio propio para auditar, puedes usar OWASP Juice Shop.

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
| **URL objetivo** | La dirección del sitio a auditar. Para un sitio público, pon la URL completa (por ejemplo `https://midominio.com`). Si el sitio corre en tu propia máquina y usas Docker, usa `http://host.docker.internal:PUERTO` en lugar de `http://localhost:PUERTO`, porque `localhost` dentro del contenedor apunta a sí mismo. |
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

> Para tu primera corrida, usa `limite_acciones` bajo (de 5 a 8): la sesión es más
> corta y puedes revisar con calma en los logs qué hizo el agente.
