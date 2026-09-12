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

Docker levanta la app, Ollama y las herramientas en un solo paso.

```bash
# 1) Clona el repositorio
git clone https://github.com/NahtanDevFS/herramienta_auditoria.git
cd herramienta_auditoria

# 2) Crea tu configuración a partir del ejemplo
cp config.yaml.example config.yaml
#    Edita config.yaml: define tu objetivo y pon 'autorizacion_confirmada: true'

# 3) Levanta todo (la primera vez descarga el modelo automáticamente)
docker compose up --build
```

La interfaz queda en **http://localhost:8501**.

### Opción B — Manual

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
pip install ollama python-dotenv

# 4) Instala las herramientas de sistema (Debian/Ubuntu)
sudo apt install nmap sqlmap libpango-1.0-0 libpangoft2-1.0-0 libcairo2 \
                 libgdk-pixbuf-2.0-0 shared-mime-info
#    nuclei: descárgalo de https://github.com/projectdiscovery/nuclei/releases

# 5) Crea tu configuración
cp config.yaml.example config.yaml
#    Edita config.yaml con tu objetivo y autorizacion_confirmada: true
```

---

## Uso

### 1. Configura el objetivo

Edita `config.yaml`:

```yaml
objetivo:
  url: "http://localhost:3000"      # tu objetivo autorizado
  autorizacion_confirmada: true     # OBLIGATORIO para ejecutar

agente_ia:
  activo: true
  modelo: "jonathanFS/pentest-owasp"
  host: "http://localhost:11434"    # en Docker: http://ollama:11434
  limite_acciones: 20               # tope de acciones del agente por sesión
  timeout_sesion_seg: 600
```

Activa o desactiva módulos en la sección `modulos:` del archivo.

### 2. Levanta un objetivo de práctica (opcional)

```bash
docker run --rm -p 3000:3000 bkimminich/juice-shop   # OWASP Juice Shop
# o sin Docker:  npx juice-shop
```

### 3. Ejecuta la auditoría

```bash
# Interfaz gráfica (recomendada)
streamlit run app_gui.py

# O por línea de comandos
python3 main.py
```

Verás en tiempo real cómo los módulos escanean, el agente analiza los hallazgos
y profundiza, y al final se genera el reporte en la carpeta `resultados/`.

> Para tu primera corrida, usa `limite_acciones` bajo (5–8): la sesión es más
> corta y puedes revisar con calma en los logs qué hizo el agente.