# Herramienta de Auditoría de Seguridad Web (OWASP Top 10)

Auditoría automatizada de seguridad web con un **agente de pentesting basado en
un modelo de lenguaje local** (Qwen2.5 fine-tuneado, servido por Ollama). Ejecuta
módulos de escaneo, deja que el agente profundice sobre los hallazgos, y genera
un reporte HTML/PDF mapeado al OWASP Top 10.

> ⚠️ **Uso ético.** Solo debes auditar sistemas propios o con autorización
> escrita. La herramienta se bloquea si `autorizacion_confirmada` no está en
> `true`. Para practicar legalmente usa laboratorios como **OWASP Juice Shop**,
> **DVWA** o **WebGoat**.

---

## Novedad: el agente ahora usa un modelo LOCAL (ya no Gemini)

El módulo `modulos/agente_pentesting.py` fue migrado de la API de Gemini a
**Ollama**, así que ya no necesitas API keys ni conexión a la nube. La lógica
de guardarraíles (whitelist de dominio, límite de acciones, métodos permitidos)
es idéntica; solo cambió el "cerebro".

---

## Instalación fácil con Docker (recomendada)

Requisito único: **Docker** y **Docker Compose**. No instalas nmap, sqlmap,
nuclei, Ollama ni las librerías del PDF a mano: van dentro de los contenedores.

```bash
# 1) Prepara tu configuración
cp config.yaml.example config.yaml
#    edita config.yaml: pon tu objetivo y autorizacion_confirmada: true

# 2) Indica qué modelo usar (el que publicaste en Ollama; ver más abajo)
export OLLAMA_MODEL=tu_usuario/pentest-owasp

# 3) Levanta todo
docker compose up --build
```

Luego abre **http://localhost:8501** para la interfaz web.

La primera vez, el servicio `model-loader` descarga tu modelo en Ollama (puede
tardar según el tamaño). Los reportes quedan en `./resultados`.

---

## ¿De dónde sale el modelo `pentest-owasp`?

Es el modelo que entrenas tú (fine-tuning QLoRA de Qwen2.5). El flujo:

1. **Entrenas** en Colab/GPU y **exportas a GGUF** (Unsloth:
   `model.save_pretrained_gguf(...)`), lo que te deja un `.gguf` + un `Modelfile`.
2. Lo **cargas en Ollama** de una de dos formas:

**Opción A — publicarlo (para que cualquiera lo instale):**
```bash
ollama create pentest-owasp -f Modelfile
ollama cp pentest-owasp tu_usuario/pentest-owasp
ollama push tu_usuario/pentest-owasp
```
Con esto, el `model-loader` del compose lo baja solo con `ollama pull`.

**Opción B — mantenerlo local (sin publicar):**
Coloca el `.gguf` y el `Modelfile` en una carpeta `./modelo/`, y en
`docker-compose.yml` comenta el `entrypoint` de la Opción A y descomenta el de
la Opción B (usa `ollama create`).

> Nota: un `.gguf` pesa varios GB, así que **no lo subas a git**. Publícalo en
> Ollama o en Hugging Face, o distribúyelo aparte.

---

## Instalación manual (para desarrollo)

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
pip install ollama python-dotenv

# Herramientas de sistema (Debian/Ubuntu):
sudo apt install nmap sqlmap libpango-1.0-0 libpangoft2-1.0-0 libcairo2 \
                 libgdk-pixbuf-2.0-0 shared-mime-info
# nuclei: descárgalo de https://github.com/projectdiscovery/nuclei/releases

# Ollama + tu modelo:
# instala Ollama desde https://ollama.com, luego:
ollama create pentest-owasp -f Modelfile

# Configura y ejecuta:
cp config.yaml.example config.yaml   # y edítalo
streamlit run app_gui.py             # interfaz web
# o por línea de comandos:
python3 main.py
```

> **Sobre `requirements.txt`:** los pines actuales son muy específicos y
> bleeding-edge (numpy/pandas/transformers), lo que rompe fácil en otras
> máquinas. Si no usas Docker, considera relajarlos (usar `>=` en vez de `==`)
> o generar un `requirements.txt` limpio desde un entorno que funcione.

---

## Los tres requisitos del proyecto, y dónde viven

| Requisito | Dónde está |
|---|---|
| Agente que ejecuta herramientas sobre la web | `modulos/agente_pentesting.py` (loop de function calling) |
| Contexto = reporte preliminar de otras herramientas | `auditoria.py` pasa `_hallazgos_previos` al agente |
| Ver visualmente las acciones | `app_gui.py` (Streamlit + `callback_progreso`) |
| Reporte de hallazgos | `core/reporte_html.py` (HTML/PDF) |
| **Modelo hecho por ti** | fine-tuning QLoRA de Qwen2.5 → GGUF → Ollama |

---

## Advertencia técnica sobre el modelo fine-tuneado y las tools

Tu modelo afinado es fuerte en **razonamiento de seguridad y redacción**, pero
el fine-tuning puede degradar la fiabilidad del **function calling** (formato
estricto de las llamadas a herramientas). Si notas que el agente propone
herramientas mal formadas:

- Sube `limite_acciones` y prueba el prompt del sistema.
- Como plan B, usa el **Qwen2.5-Instruct base** para el loop del agente y tu
  modelo afinado para la parte de análisis/redacción del reporte.
- Documentar este trade-off (rendimiento de dominio vs. fiabilidad de tools) es
  buen material para el informe del curso.
