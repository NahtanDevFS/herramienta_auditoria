import glob
import json
import logging
import os

import streamlit as st
from dotenv import load_dotenv

from auditoria import ejecutar_auditoria
from core.reporte_html import generar as generar_informe

load_dotenv()

st.set_page_config(
    page_title="Auditoria de Seguridad Web",
    page_icon="[S]",
    layout="wide",
)

COLOR_SEV = {
    "critica": "#8B0000", "alta": "#D32F2F", "media": "#F57C00",
    "baja": "#FBC02D", "informativa": "#0288D1",
}
COLOR_NIVEL = {
    "Critico": "#8B0000", "Alto": "#D32F2F", "Medio": "#F57C00",
    "Bajo": "#FBC02D", "Informativo": "#90A4AE",
}

MODULOS_INFO = {
    "cabeceras_http": ("Cabeceras HTTP (A02)", "Revisa cabeceras de seguridad."),
    "cookies": ("Cookies (A04)", "Flags Secure, HttpOnly, SameSite."),
    "tls_ssl": ("TLS/SSL (A04)", "Certificado y protocolos."),
    "archivos_expuestos": ("Archivos expuestos (A02)", ".git, .env, backups."),
    "tecnologias": ("Tecnologias (A03)", "Stack y versiones."),
    "nuclei": ("Nuclei (varios)", "Escaneo por plantillas/CVE."),
    "puertos_nmap": ("Nmap (A02)", "Puertos y servicios."),
    "crawler": ("Crawler (recon)", "Rutas, formularios, parametros."),
    "sqlmap": ("SQLmap (A05)", "Inyeccion SQL (requiere URLs)."),
    "zap": ("OWASP ZAP (varios)", "Escaneo activo XSS/injection."),
    "metodos_http": ("Metodos HTTP (A01)", "PUT/DELETE/TRACE, traversal."),
    "autenticacion": ("Autenticacion (A07)", "Rate limiting, sesion."),
    "agente_ia": ("Agente de IA (A01/A05)", "Analisis contextual con modelo local (Ollama)."),
}


def configurar_logger():
    logger = logging.getLogger("auditoria_gui")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s",
                                           datefmt="%H:%M:%S"))
    logger.addHandler(handler)
    return logger


# ejecuta la auditoria en un proceso hijo para poder cancelarla (matando chromium/ollama)
def _worker_auditoria(config, ruta_log, ruta_estado, cola):
    # escribe log y progreso para la ui y envia resultado final por la cola
    os.setsid()  # nuevo grupo de procesos > permite matar todo el arbol al detener
    logger = logging.getLogger("auditoria_worker")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    fh = logging.FileHandler(ruta_log, mode="w", encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s",
                                       datefmt="%H:%M:%S"))
    logger.addHandler(fh)

    def cb(indice, total, nombre_modulo):
        try:
            with open(ruta_estado, "w", encoding="utf-8") as f:
                json.dump({"indice": indice, "total": total,
                           "modulo": nombre_modulo}, f)
        except Exception:
            pass

    try:
        reporte = ejecutar_auditoria(config, logger, callback_progreso=cb)
        datos = reporte.construir()
        carpeta = config.get("salida", {}).get("carpeta", "resultados")
        reporte.guardar_json(carpeta)
        rutas = generar_informe(datos, carpeta, ["html", "pdf"], logger)
        videos = sorted(glob.glob(os.path.join(carpeta, "video", "*.webm")),
                        key=os.path.getmtime, reverse=True)
        cola.put({"ok": True, "datos": datos, "rutas": rutas,
                  "video": videos[0] if videos else None})
    except Exception as e:
        logger.error(f"Error en la auditoria: {e}")
        try:
            cola.put({"ok": False, "error": str(e)})
        except Exception:
            pass

    # si hay navegador abierto, mantenemos el proceso vivo para no cerrar chromium
    if config.get("_navegador_abierto") is not None:
        import time as _t
        while True:
            _t.sleep(3600)


def _matar_proceso(proc):
    # mata un proceso worker y todo su grupo (chromium, ventana de razonamiento)
    import signal
    if proc is None or not proc.pid:
        return
    for sig in (signal.SIGTERM, signal.SIGKILL):
        if not proc.is_alive():
            break
        try:
            os.killpg(os.getpgid(proc.pid), sig)
        except OSError:
            try:
                proc.terminate() if sig == signal.SIGTERM else proc.kill()
            except Exception:
                pass
        proc.join(timeout=5)


def _cerrar_navegador_abierto():
    # cierra el navegador que quedo abierto de una auditoria anterior (si lo hay)
    prev = st.session_state.pop("proc_navegador", None)
    if prev is not None:
        _matar_proceso(prev)


def _lanzar_auditoria_en_proceso(config, mostrar_monitor):
    import multiprocessing
    import tempfile
    # cerrar el navegador que hubiera quedado abierto de una corrida anterior
    _cerrar_navegador_abierto()
    ctx = multiprocessing.get_context("fork")  # fork: el hijo no reimporta app_gui
    base = tempfile.gettempdir()
    ruta_log = os.path.join(base, "auditoria_live.log")
    ruta_estado = os.path.join(base, "auditoria_estado.json")
    for p in (ruta_log, ruta_estado):
        try:
            os.remove(p)
        except OSError:
            pass
    cola = ctx.Queue()
    proc = ctx.Process(target=_worker_auditoria,
                       args=(config, ruta_log, ruta_estado, cola))
    proc.start()
    st.session_state.proc = proc
    st.session_state.cola = cola
    st.session_state.ruta_log = ruta_log
    st.session_state.ruta_estado = ruta_estado
    st.session_state.mostrar_monitor = mostrar_monitor


def _limpiar_estado_auditoria():
    st.session_state.auditoria_en_curso = False
    for k in ("proc", "cola", "ruta_log", "ruta_estado"):
        st.session_state.pop(k, None)


def _detener_auditoria():
    # mata el worker y cierra cualquier navegador abierto previo
    _matar_proceso(st.session_state.get("proc"))
    _cerrar_navegador_abierto()
    _limpiar_estado_auditoria()
    st.session_state["error_auditoria"] = "Auditoria detenida por el usuario."


def _render_monitor(expanded=True):
    # panel desplegable del monitor en vivo (novnc)
    import streamlit.components.v1 as components
    with st.expander("Monitor en Vivo (Escritorio Virtual)", expanded=expanded):
        vnc_html = """
        <div style="position:relative;width:100%;padding-bottom:56.25%;overflow:hidden;">
            <iframe
                src="http://localhost:8080/vnc.html?autoconnect=true&resize=scale"
                style="position:absolute;top:0;left:0;width:100%;height:100%;border:none;"
                allowfullscreen>
            </iframe>
        </div>
        """
        components.html(vnc_html, height=700)
        st.caption("Puedes plegar o desplegar este panel con la flecha de arriba. "
                   "Si no ves imagen, verifica que mapeaste -p 8080:8080.")


@st.fragment(run_every="1s")
def _panel_en_curso():
    # se refresca cada segundo sin recargar el resto de la pagina (evita parpadeo de novnc)
    proc = st.session_state.get("proc")
    cola = st.session_state.get("cola")
    ruta_log = st.session_state.get("ruta_log")
    ruta_estado = st.session_state.get("ruta_estado")

    # (el boton de detener vive en el sidebar, para que sea siempre visible )

    # barra de progreso (desde el archivo de estado)
    indice, total, modulo = 0, 0, "preparando"
    try:
        with open(ruta_estado, encoding="utf-8") as f:
            e = json.load(f)
        indice, total, modulo = e.get("indice", 0), e.get("total", 0), e.get("modulo", "")
    except Exception:
        pass
    pct = int(indice / max(total, 1) * 100)
    st.progress(pct, text=f"Ejecutando: {modulo} ({indice}/{max(total, 1)})")

    # terminal de progreso en vivo (ultimas lineas del log)
    st.markdown("**Terminal de progreso**")
    try:
        with open(ruta_log, encoding="utf-8") as f:
            lineas = f.readlines()[-14:]
        st.code("".join(lineas).strip() or "Iniciando...", language="text")
    except Exception:
        st.code("Iniciando...", language="text")

    # resultado disponible en la cola?
    resultado = None
    if cola is not None:
        try:
            resultado = cola.get_nowait()
        except Exception:
            resultado = None

    # si el proceso ya murio y aun no hay resultado, dar un instante por si llega
    if resultado is None and proc is not None and not proc.is_alive():
        try:
            resultado = cola.get(timeout=1)
        except Exception:
            resultado = None
        if resultado is None:
            _limpiar_estado_auditoria()  # murio sin dejar resultado
            st.rerun()
            return

    if resultado is not None:
        if resultado.get("ok"):
            st.session_state["datos_reporte"] = resultado["datos"]
            st.session_state["rutas_informe"] = resultado["rutas"]
            st.session_state["video_agente"] = resultado.get("video")
        else:
            st.session_state["error_auditoria"] = resultado.get("error", "desconocido")
        # mantiene el handle del navegador abierto para cerrarlo despues
        cfg_ag = (st.session_state.get("config_auditoria", {}) or {}).get("agente_ia", {})
        if cfg_ag.get("mantener_navegador_abierto") and proc is not None and proc.is_alive():
            st.session_state["proc_navegador"] = proc
        _limpiar_estado_auditoria()
        st.rerun()


st.title("Herramienta de Auditoria de Seguridad Web")
st.caption("Analisis segun OWASP Top 10")

# barra lateral: configuracion
with st.sidebar:
    st.header("Configuracion")

    url = st.text_input("URL objetivo", placeholder="http://localhost:3000",
                        help="Incluye http:// o https://")
    nombre = st.text_input("Nombre del objetivo", value="Auditoria")

    st.divider()
    st.subheader("Modulos a ejecutar")

    col_a, col_b = st.columns(2)
    if col_a.button("Marcar todos", width='stretch'):
        for clave in MODULOS_INFO:
            st.session_state[f"mod_{clave}"] = True
    if col_b.button("Desmarcar todos", width='stretch'):
        for clave in MODULOS_INFO:
            st.session_state[f"mod_{clave}"] = False

    modulos_activos = {}
    for clave, (titulo, desc) in MODULOS_INFO.items():
        default = clave not in ("zap", "nmap", "sqlmap", "puertos_nmap")
        modulos_activos[clave] = st.checkbox(
            titulo, value=st.session_state.get(f"mod_{clave}", default),
            key=f"mod_{clave}", help=desc,
        )

    st.divider()
    st.subheader("Opciones avanzadas")
    verificar_ssl = st.checkbox("Verificar certificado SSL", value=True,
                                help="Desactivar para certificados autofirmados.")
    
    default_zap = "/usr/local/bin/zap.sh" if os.path.exists("/usr/local/bin/zap.sh") else os.path.expanduser("~/proyectos/ZAP_2.17.0/zap.sh")
    ruta_zap = st.text_input("Ruta a zap.sh (si usas ZAP)", value=default_zap)

    # configuracion del agente de IA (modelo local via ollama)
    modelo_ollama = "jonathanFS/pentest-owasp"
    host_ollama = "http://localhost:11434"
    usar_navegador = True
    abrir_ventana = True
    ventana_pensamiento = True
    cred_usuario = ""
    cred_contrasena = ""
    limite_acciones_agente = 20
    timeout_agente = 600
    if modulos_activos.get("agente_ia"):
        st.divider()
        st.subheader("Agente de IA (modelo local)")
        modelo_ollama = st.text_input("Modelo en Ollama", value="jonathanFS/pentest-owasp")
        host_ollama = st.text_input("Host de Ollama",
                                    value=os.environ.get("OLLAMA_HOST", "http://localhost:11434"))
        usar_navegador = st.checkbox(
            "Modo navegador (ver acciones en vivo)", value=True,
            help="Usa Playwright para interactuar con el sitio y mostrar capturas en vivo.",
        )
        if usar_navegador:
            abrir_ventana = st.checkbox(
                "Mostrar navegador visualmente (Monitor en vivo noVNC)", value=True,
                help="Arranca el navegador de forma visible en el escritorio virtual integrado de Docker.",
            )
        ventana_pensamiento = st.checkbox(
            "Ventana de pensamiento del agente", value=True,
            help="Abre una ventana flotante con el razonamiento del agente en el monitor virtual.",
        )
        st.markdown("**Credenciales (opcional)** — para auditar la zona autenticada")
        cred_usuario = st.text_input("Usuario / email", value="",
                                     help="Solo para auditar TU propia web. Si lo dejas "
                                          "vacio, la auditoria corre sin iniciar sesion.")
        cred_contrasena = st.text_input("Contraseña", value="", type="password")
        limite_acciones_agente = st.number_input("Limite de acciones por sesion",
                                                 min_value=1, max_value=50, value=20)
        timeout_agente = st.number_input("Timeout de sesion (segundos)",
                                         min_value=60, max_value=1800, value=600, step=60)
        st.caption(
            "El agente solo actua dentro del dominio del objetivo, no ejecuta "
            "acciones destructivas y se detiene al llegar al limite o al timeout."
        )

    st.divider()
    autorizado = st.checkbox(
        "Confirmo que tengo AUTORIZACION para auditar este objetivo", value=False)

    if "auditoria_en_curso" not in st.session_state:
        st.session_state.auditoria_en_curso = False

    lanzar = st.button("Iniciar auditoria", type="primary",
                       use_container_width=True,
                       disabled=(not autorizado or st.session_state.auditoria_en_curso))

    # boton de detener: solo visible mientras hay una auditoria en curso, en rojo
    if st.session_state.get("auditoria_en_curso"):
        st.markdown(
            "<style>"
            ".st-key-btn_detener button{background:#D32F2F !important;"
            "color:#fff !important;border:none !important;font-weight:700 !important;}"
            ".st-key-btn_detener button:hover{background:#B71C1C !important;"
            "color:#fff !important;}"
            "</style>",
            unsafe_allow_html=True)
        if st.button("⏹ Detener auditoria", key="btn_detener",
                     use_container_width=True):
            _detener_auditoria()
            st.rerun()

# zona principal
if not url:
    st.info("Introduce una URL objetivo en la barra lateral para comenzar.")
    st.stop()

if lanzar:
    if not (url.startswith("http://") or url.startswith("https://")):
        st.error("La URL debe empezar por http:// o https://")
        st.stop()
    if not autorizado:
        st.error("Debes confirmar la autorizacion para auditar.")
        st.stop()

    # lanza proceso de auditoria en segundo plano cancelable
    st.session_state.config_auditoria = {
        "objetivo": {"url": url, "nombre": nombre, "autorizacion_confirmada": True},
        "modulos": modulos_activos,
        "opciones": {"timeout": 10, "verificar_ssl": verificar_ssl,
                     "user_agent": "AuditoriaWeb/1.0 (GUI)"},
        "salida": {"carpeta": "resultados"},
        "nuclei": {"severidades": "medium,high,critical", "timeout": 300},
        "nmap": {"top_ports": 1000, "timeout": 300},
        "zap": {"ruta": ruta_zap, "active_scan": True,
                "timeout_spider": 300, "timeout_ascan": 900},
        "crawler": {"max_paginas": 50, "max_profundidad": 3},
        "sqlmap": {"urls": [], "level": 1, "risk": 1, "timeout": 180},
        "agente_ia": {
            "activo": modulos_activos.get("agente_ia", False),
            "modelo": modelo_ollama,
            "host": host_ollama,
            "navegador": usar_navegador,
            "headless": not abrir_ventana,
            "ventana_pensamiento": ventana_pensamiento,
            "usuario": cred_usuario.strip(),
            "contrasena": cred_contrasena,
            "limite_acciones": limite_acciones_agente,
            "timeout_sesion_seg": timeout_agente,
            # dejar el navegador abierto al terminar (solo tiene sentido si es visible)
            "mantener_navegador_abierto": bool(
                modulos_activos.get("agente_ia") and usar_navegador and abrir_ventana),
        },
    }
    st.session_state.mostrar_monitor = bool(
        modulos_activos.get("agente_ia") and usar_navegador and abrir_ventana)
    # limpia resultados de auditoria previa
    for k in ("datos_reporte", "rutas_informe", "video_agente", "error_auditoria"):
        st.session_state.pop(k, None)
    st.session_state.auditoria_en_curso = True
    st.rerun()

if st.session_state.get("auditoria_en_curso", False):
    # primera pasada: lanzar el proceso de auditoria en segundo plano
    if st.session_state.get("proc") is None:
        _lanzar_auditoria_en_proceso(
            st.session_state.get("config_auditoria", {}),
            st.session_state.get("mostrar_monitor", False))

    # panel de progreso + terminal en vivo (arriba)
    _panel_en_curso()

    # monitor fuera del fragmento para evitar recargar iframe en cada avance
    if st.session_state.get("mostrar_monitor"):
        _render_monitor(expanded=True)

# mantiene monitor disponible despues de terminar la auditoria
elif st.session_state.get("mostrar_monitor"):
    _render_monitor(expanded=True)


# aviso si la ultima auditoria fue detenida o fallo
if st.session_state.get("error_auditoria") and not st.session_state.get("auditoria_en_curso"):
    st.warning(st.session_state["error_auditoria"])

# mostrar resultados (si existen y no hay una auditoria en curso)
if "datos_reporte" in st.session_state and not st.session_state.get("auditoria_en_curso"):
    datos = st.session_state["datos_reporte"]
    meta = datos["metadatos"]
    analisis = datos.get("analisis_riesgo", {})
    valoracion = analisis.get("valoracion_global", {})

    st.divider()
    st.header("Resultados")

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total hallazgos", meta["total_hallazgos"])
    if valoracion:
        c2.metric("Riesgo global", valoracion.get("nivel", "-"),
                  f"{valoracion.get('puntuacion', 0)}/10")
    resumen = datos["resumen_por_severidad"]
    c3.metric("Criticos + Altos", resumen.get("critica", 0) + resumen.get("alta", 0))
    c4.metric("Duracion", f"{meta['duracion_segundos']:.0f}s")

    if valoracion:
        color = COLOR_NIVEL.get(valoracion.get("nivel"), "#607D8B")
        st.markdown(
            f"<div style='background:{color};color:white;padding:20px;"
            f"border-radius:8px;text-align:center;'>"
            f"<span style='font-size:36px;font-weight:bold;'>"
            f"{valoracion.get('puntuacion')}/10</span><br>"
            f"<span style='font-size:18px;'>Riesgo {valoracion.get('nivel','')}</span>"
            f"</div>", unsafe_allow_html=True)
        st.write(valoracion.get("descripcion", ""))

    # video del agente (si existe)
    video_agente = st.session_state.get("video_agente")
    if video_agente and os.path.isfile(video_agente):
        with st.expander("Ver Grabacion de la Sesion del Agente", expanded=False):
            st.video(video_agente)

    st.subheader("Distribucion por severidad")
    cols = st.columns(5)
    for col, (sev, cant) in zip(cols, resumen.items()):
        col.markdown(
            f"<div style='background:{COLOR_SEV[sev]};color:white;padding:12px;"
            f"border-radius:6px;text-align:center;'>"
            f"<span style='font-size:24px;font-weight:bold;'>{cant}</span><br>"
            f"<span style='font-size:12px;'>{sev.capitalize()}</span></div>",
            unsafe_allow_html=True)

    matriz = analisis.get("matriz")
    if matriz:
        st.subheader("Matriz de riesgo (Impacto x Probabilidad)")
        html = "<table style='border-collapse:collapse;margin:auto;'>"
        html += "<tr><th style='padding:8px;'>I\\P</th>"
        for p in range(1, 6):
            html += f"<th style='padding:8px;'>{p}</th>"
        html += "</tr>"
        for fila in matriz["celdas"]:
            html += f"<tr><th style='padding:8px;'>{fila[0]['impacto']}</th>"
            for celda in fila:
                color = COLOR_NIVEL.get(celda["nivel"], "#ccc")
                n = celda["cantidad"] if celda["cantidad"] > 0 else ""
                html += (f"<td style='background:{color};color:white;width:55px;"
                         f"height:45px;text-align:center;font-weight:bold;"
                         f"font-size:16px;'>{n}</td>")
            html += "</tr>"
        html += "</table>"
        st.markdown(html, unsafe_allow_html=True)
        st.caption("Vertical: Impacto (1-5) | Horizontal: Probabilidad (1-5)")

    st.subheader("Hallazgos")
    por_categoria = {}
    for h in datos["hallazgos"]:
        por_categoria.setdefault(h["categoria"], []).append(h)

    for categoria, lista in por_categoria.items():
        with st.expander(f"{categoria} ({len(lista)})"):
            for h in lista:
                color = COLOR_SEV.get(h["severidad"], "#999")
                cvss = f" | CVSS {h['cvss']}" if h.get("cvss") else ""
                st.markdown(
                    f"<span style='background:{color};color:white;padding:2px 8px;"
                    f"border-radius:3px;font-size:12px;'>{h['severidad'].upper()}"
                    f"</span> **{h['titulo']}**{cvss}", unsafe_allow_html=True)
                st.write(h["descripcion"])
                if h.get("evidencia"):
                    st.code(h["evidencia"], language=None)
                if h.get("recomendacion"):
                    st.caption(f"Recomendacion: {h['recomendacion']}")
                st.divider()

    st.subheader("Descargar informe")
    if "rutas_informe" in st.session_state:
        cols = st.columns(len(st.session_state["rutas_informe"]) + 1)
        cols[0].download_button(
            "Descargar JSON",
            data=json.dumps(datos, ensure_ascii=False, indent=2),
            file_name="informe.json", mime="application/json")
        for i, ruta in enumerate(st.session_state["rutas_informe"], 1):
            if os.path.isfile(ruta):
                with open(ruta, "rb") as f:
                    ext = ruta.rsplit(".", 1)[-1].upper()
                    cols[i].download_button(f"Descargar {ext}", data=f.read(),
                                            file_name=os.path.basename(ruta))