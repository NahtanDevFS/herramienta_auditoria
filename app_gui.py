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


st.title("Herramienta de Auditoria de Seguridad Web")
st.caption("Analisis segun OWASP Top 10")

# --- Barra lateral: configuracion ---
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

    # --- Configuracion del agente de IA (modelo LOCAL via Ollama) ---
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

    lanzar = st.button("Iniciar auditoria", type="primary",
                       width='stretch', disabled=not autorizado)


# --- Zona principal ---
if not url:
    st.info("Introduce una URL objetivo en la barra lateral para comenzar.")
    st.stop()

if modulos_activos.get("agente_ia") and usar_navegador and abrir_ventana:
    st.markdown("**Monitor en Vivo (Escritorio Virtual Linux)**")
    import streamlit.components.v1 as components
    components.iframe(src="http://localhost:8080/vnc.html?autoconnect=true&resize=scale", width=1000, height=600)
    st.caption("Si no ves la imagen, asegúrate de haber mapeado el puerto 8080 al lanzar Docker (-p 8080:8080).")

if lanzar:
    if not (url.startswith("http://") or url.startswith("https://")):
        st.error("La URL debe empezar por http:// o https://")
        st.stop()
    if not autorizado:
        st.error("Debes confirmar la autorizacion para auditar.")
        st.stop()

    config = {
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
        },
    }

    logger = configurar_logger()

    barra = st.progress(0, text="Preparando auditoria...")
    estado = st.empty()

    # --- Panel de Logs en vivo ---
    st.markdown("**Terminal de progreso**")
    log_box = st.empty()
    
    class StreamlitLogHandler(logging.Handler):
        def __init__(self, placeholder):
            super().__init__()
            self.placeholder = placeholder
            self.logs = []
        def emit(self, record):
            msg = self.format(record)
            self.logs.append(msg)
            # Mantener solo unas pocas lineas para que quede de un tamano fijo y no empuje la UI
            if len(self.logs) > 4:
                self.logs.pop(0)
            self.placeholder.code("\n".join(self.logs), language="text")
            
    st_handler = StreamlitLogHandler(log_box)
    st_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S"))
    logger.addHandler(st_handler)

    def callback(indice, total, nombre_modulo):
        pct = int(indice / max(total, 1) * 100)
        barra.progress(pct, text=f"Ejecutando: {nombre_modulo} ({indice}/{total})")
        estado.info(f"En curso: **{nombre_modulo}**")



    with st.spinner("Auditoria en curso... esto puede tardar varios minutos."):
        reporte = ejecutar_auditoria(config, logger, callback_progreso=callback)

    barra.progress(100, text="Auditoria completada.")
    estado.success("Auditoria completada.")

    datos = reporte.construir()
    st.session_state["datos_reporte"] = datos

    carpeta = "resultados"
    reporte.guardar_json(carpeta)
    rutas = generar_informe(datos, carpeta, ["html", "pdf"], logger)
    st.session_state["rutas_informe"] = rutas

    # Guardar la ruta del ultimo video (si el agente uso el navegador).
    videos = sorted(glob.glob(os.path.join(carpeta, "video", "*.webm")),
                    key=os.path.getmtime, reverse=True)
    st.session_state["video_agente"] = videos[0] if videos else None


# --- Mostrar resultados (si existen) ---
if "datos_reporte" in st.session_state:
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

    # --- Video del agente (si existe) ---
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