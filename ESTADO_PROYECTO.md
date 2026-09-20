# Estado del proyecto — Herramienta de Auditoría Web con Agente IA

Documento de traspaso para continuar el desarrollo en otra sesión.
Repo: https://github.com/NahtanDevFS/herramienta_auditoria

---

## 1. Qué es el proyecto

Herramienta de auditoría de seguridad web (OWASP Top 10) que combina módulos de
escaneo tradicionales con un **agente de pentesting autónomo basado en un LLM
local** (modelo propio, fine-tuneado). El agente recibe el reconocimiento como
contexto, actúa sobre él con un navegador real, confirma vulnerabilidades y
genera hallazgos. Objetivo de uso: que una persona pueda auditar su propia web.

**Modelo:** Qwen2.5-7B fine-tuneado con QLoRA (Unsloth) sobre dataset de OWASP
(Fenrir), publicado en el registro de Ollama como **`jonathanFS/pentest-owasp`**.
Corre 100% local vía Ollama.

---

## 2. Arquitectura y flujo

Módulos de escaneo (orquestados por `auditoria.py`, config compartido entre todos):
cabeceras_http, cookies, tls_ssl, archivos_expuestos, tecnologias, nuclei, nmap,
**crawler**, sqlmap, zap, metodos_http, autenticacion, **agente_ia**.

Flujo del agente (lo relevante de este proyecto):

1. **Crawler** (`modulos/crawler.py` + `crawler_worker.py`): rastrea con
   renderizado de JavaScript (Playwright en **subproceso** — no puede correr en
   el bucle de asyncio de Streamlit). Descubre rutas, formularios, y captura
   **endpoints de API** escuchando el tráfico de red. Deja en el config
   compartido: `_mapa_sitio`, `_rutas_descubiertas`, `_endpoints_api`.
2. **Agente** (`modulos/agente_pentesting.py`): usa el modelo local (Ollama) con
   un navegador real (`modulos/navegador.py`, Playwright).
   - Construye **objetivos de cobertura** (deterministas, sembrados desde las
     rutas descubiertas + patrones conocidos).
   - **Bucle de cobertura obligatoria**: no deja terminar hasta cubrir todos.
   - Herramientas visibles: `analizar_pagina`, `probar_login`, `probar_busqueda`,
     `probar_formulario`, `probar_idor`.
   - **Presupuesto de intentos por objetivo** (evita martilleo infinito).
   - **Barrido automático de API** al final (determinista, no lo decide el modelo).
   - **Login real opcional** (paso previo determinista con credenciales).
   - **Ventana de pensamiento** (Tkinter en subproceso) muestra el razonamiento.
3. **Reporte** (`core/reporte_html.py`): HTML/PDF con hallazgos, matriz de riesgo,
   CVSS, mapeado a OWASP.

Interfaz: **Streamlit** (`app_gui.py`), con panel en vivo y video de la sesión.

---

## 3. Lo que YA está hecho

- [x] Modelo entrenado (QLoRA/Unsloth) y publicado en Ollama (`jonathanFS/pentest-owasp`).
- [x] Migración del agente de Gemini (nube) a **Ollama local**.
- [x] Empaquetado con Docker + README para instalación por terceros.
- [x] **Crawler con render JS** (Playwright en subproceso, evita el choque con Streamlit).
- [x] **Captura de endpoints de API** escuchando el tráfico de red.
- [x] El crawler **dispara una búsqueda** para capturar la API de búsqueda de forma consistente.
- [x] **Mapa estructurado** + **siembra determinista de objetivos** (login, search, contact, register).
- [x] **Bucle de cobertura obligatoria** (exhaustividad garantizada por código).
- [x] Herramientas visibles del navegador (login, búsqueda, formulario genérico, IDOR, analizar).
- [x] **Auto-registro de hallazgos** + deduplicación por firma + bloqueo del registro manual A05 en modo navegador (evita duplicados/falsos positivos/texto corrupto del modelo).
- [x] **Presupuesto de intentos por objetivo** (4 intentos; luego "probado/seguro" y avanza). Resuelve el martilleo y el caso "login seguro".
- [x] **Barrido automático de API** (determinista): prueba endpoints con inyección, detecta errores SQL (auto-registra) y JSON sin auth (señala A01).
- [x] **Ventana del navegador visible** (headed, vía WSLg) — para la demo presencial.
- [x] **Ventana de pensamiento** flotante (razonamiento en vivo, subproceso Tkinter).
- [x] **Login real con credenciales** como paso previo determinista (FUNCIONA: inicia sesión y confirma token).

---

## 4. Lo que está PENDIENTE (próximos pasos)

### 4.1. EN CURSO — Auditoría autenticada fiable (lo siguiente a hacer)
El login real ya entra correctamente, PERO cuando el modelo explora la zona
privada "a su aire" se descarrila (inventa URLs, se va a sitios externos,
navega sin rumbo hasta cortarse por bucle). **Decisión tomada:** no dejar que el
modelo explore libre; en su lugar:
- Quitar del prompt la instrucción de "exploración libre autenticada".
- **Sembrar objetivos DETERMINISTAS de IDOR/acceso** sobre endpoints de API
  privados (p.ej. `/rest/basket/N`, `/api/Users`, historial de pedidos), que
  autenticado sí son accesibles.
- Probarlos en el **barrido automático de API extendido** (determinista), que ya
  funciona bien. Autenticado, el barrido cobra más valor porque alcanza recursos
  privados donde viven los IDOR reales.
- Prioridad confirmada por el usuario: **endpoints de API privados** (fiabilidad)
  por encima de navegación visual de la zona privada.

### 4.2. Afinar heurística A01 del barrido de API
La regla "JSON con HTTP 200 sin auth = posible A01" da **falsos positivos**
(muchas APIs devuelven datos públicos legítimos). Restringir el auto-señalado a
endpoints con nombres claramente sensibles (user, admin, account, order, basket).

### 4.3. Verificación más rigurosa (menos falsos positivos)
- SQLi **diferencial**: comparar respuesta de `' OR 1=1` vs `' OR 1=2`.
- XSS: confirmar que el script **ejecuta** (detectar el diálogo/alert), no solo
  que el payload se refleja.

### 4.4. Robustez de ingeniería
- **Reintentos guiados**: si el modelo genera una llamada mal formada, devolverle
  el error con una pista para que corrija (en vez de perder la acción).

### 4.5. Detalles menores (cosméticos, no urgentes)
- [ ] Aplicar el fix del warning de Streamlit (nunca se aplicó):
      `sed -i "s/use_container_width=True/width='stretch'/g" app_gui.py`
- [ ] El modelo a veces registra el bypass como categoría **A01** en vez de A05
      (ya se deduplica igual; es cosmético).
- [ ] "IDOR inventado": el modelo a veces prueba `probar_idor` sobre URLs que no
      existen. Se podría restringir a URLs realmente presentes en el mapa.

### 4.6. Ampliaciones futuras (opcionales, si sobra tiempo)
- XSS **almacenado** (no solo reflejado), CSRF, control de acceso a rutas de admin.
- Modelo más capaz (14B) o mejor dataset de fine-tuning con las trayectorias que
  ya se generan en estas auditorías. **Recomendado al final**, no antes: el mayor
  impacto está en herramientas + determinismo, no en el tamaño del modelo.
- Documentar limitaciones en el README (ver sección 5) — suma en la evaluación.

---

## 5. Limitaciones conocidas (documentar en el informe)

- **El 7B es variable:** rinde muy bien cuando el código le da objetivos concretos
  y deterministas; se dispersa e inventa cuando se le da libertad sin estructura.
  Esta es la lección transversal del proyecto: *lo crítico se hace por código,
  el modelo confirma.*
- **Detección de XSS por reflejo** puede dar falsos positivos (no confirma ejecución).
- **Heurística A01** (JSON sin auth) da falsos positivos.
- **Rastreo de SPAs oportunista** (mitigado con la siembra de objetivos).
- **Fine-tuning degrada la seguridad del modelo** (efecto documentado en la literatura).

---

## 6. Notas técnicas para continuar (IMPORTANTE)

**Entorno:**
- WSL2 Ubuntu sobre Windows 11, con **WSLg** activo (`echo $DISPLAY` → `:0`).
- El venv se creó con `--system-site-packages` para que vea **tkinter**
  (instalado por apt: `python3-tk`; no se puede instalar por pip).
- **Ollama corre en Windows** (no en WSL). Red en modo **mirrored**
  (`.wslconfig` → `networkingMode=mirrored`), así `localhost:11434` funciona
  desde WSL.
- Usar `python3` (no `python`). Los subprocesos usan `sys.executable` (venv), OK.

**Reglas de oro aprendidas:**
- **Reiniciar Streamlit tras CUALQUIER cambio de código** — no recarga módulos en
  caliente (varias veces pareció "no funcionar" y era esto).
- **Mantener el repo de GitHub sincronizado** con el local — hubo desincronización
  (features corriendo en local pero no pusheadas). Commitear/pushear siempre.
- **Playwright + Streamlit:** el crawler corre Playwright en **subproceso** (choca
  con el asyncio de Streamlit); el agente lo corre en-proceso y funciona.

**Objetivo de pruebas:**
- OWASP Juice Shop: `docker run --rm -p 3000:3000 bkimminich/juice-shop`
- Usuario de prueba creado: **test@test.com / 12345** (pregunta de seguridad
  respondida). ⚠️ La BD de Juice Shop es **efímera**: si se reinicia el
  contenedor, hay que recrear el usuario en `/#/register`.

**Config del agente (en el GUI / config.yaml, sección `agente_ia`):**
- `modelo`, `host`, `navegador` (bool), `headless` (bool — false = ventana visible),
  `ventana_pensamiento` (bool), `usuario` + `contrasena` (login real opcional),
  `limite_acciones`, `timeout_sesion_seg`.

---

## 7. Mapa de archivos clave

```
modulos/
  crawler.py             # lanza el worker en subproceso, expone mapa/rutas/endpoints
  crawler_worker.py      # rastreo con render JS + captura de API (subproceso)
  navegador.py           # NavegadorAgente (Playwright): tools visibles + iniciar_sesion
  agente_pentesting.py   # NÚCLEO: loop del agente, cobertura, barrido API, login real
  ventana_pensamiento.py # ventana flotante de razonamiento (Tkinter, subproceso)
  ... (otros módulos de escaneo)
core/
  modelo_hallazgo.py     # estructura Hallazgo
  reporte_html.py        # generación de reporte HTML/PDF
app_gui.py               # interfaz Streamlit (raíz)
auditoria.py             # orquestación de módulos (raíz)
main.py                  # interfaz de línea de comandos (raíz)
```

**Dónde vive cada cosa dentro de `agente_pentesting.py`:**
- `_construir_objetivos()` — siembra de objetivos (aquí van los IDOR autenticados).
- `_seleccionar_endpoints_api()` — selección para el barrido.
- `ejecutar()` — login real (paso previo), loop, cobertura, presupuesto, barrido API.
- `SesionAgente._probar_endpoint_api()` — prueba de API (funciona; detecta SQLi real).
- `INTENTOS_POR_OBJETIVO` — presupuesto por objetivo.

---

## 8. Estado resumido

El proyecto está **funcional y sólido**: encuentra de forma autónoma y consistente
el bypass de login (SQLi, crítico), el XSS reflejado del buscador, y la inyección
SQL en la API — con exhaustividad garantizada, sin atascos, y con una demo visual
muy lograda (ventana del navegador + ventana de pensamiento). El login autenticado
ya entra correctamente. **Lo siguiente es hacer la auditoría autenticada fiable
vía objetivos deterministas de API privada (sección 4.1).**
