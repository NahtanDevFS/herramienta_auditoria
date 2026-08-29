"""
app_gui.py  (interfaz grafica - Fase 7)
---------------------------------------
Interfaz web con Streamlit para la herramienta de auditoria. Permite:
  - Configurar el objetivo y confirmar la autorizacion.
  - Activar/desactivar modulos con checkboxes.
  - Lanzar la auditoria y ver el progreso.
  - Visualizar los resultados: valoracion de riesgo, matriz, y hallazgos.
  - Descargar el informe (JSON, HTML, PDF).

Se ejecuta con:
    streamlit run app_gui.py

No sustituye a main.py (la CLI); ambos usan la misma logica de core/auditoria.py.
"""

import logging
import os
from datetime import datetime

import streamlit as st

from auditoria import ejecutar_auditoria
from core.reporte_html import generar as generar_informe


# ---------------------------------------------------------------------------
# Configuracion de la pagina
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Auditoria de Seguridad Web",
    page_icon="[S]",
    layout="wide",
)

# Colores por severidad para los indicadores visuales.
COLOR_SEV = {
    "critica": "#8B0000", "alta": "#D32F2F", "media": "#F57C00",
    "baja": "#FBC02D", "informativa": "#0288D1",
}
COLOR_NIVEL = {
    "Critico": "#8B0000", "Alto": "#D32F2F", "Medio": "#F57C00",
    "Bajo": "#FBC02D", "Informativo": "#90A4AE",
}

# Descripcion de cada modulo para mostrar en la interfaz.
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
    "agente_ia": ("Agente de IA (A01/A05)", "Analisis contextual con LLM (Gemini)."),
}

def configurar_logger():
    """Logger que ademas acumula los mensajes para mostrarlos en la GUI."""
    logger = logging.getLogger("auditoria_gui")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s",
                                           datefmt="%H:%M:%S"))
    logger.addHandler(handler)
    return logger


# Interfaz
st.title("Herramienta de Auditoria de Seguridad Web")
st.caption("Analisis segun OWASP Top 10")

# --- Barra lateral: configuracion ---
with st.sidebar:
    st.header("Configuracion")

    url = st.text_input(
        "URL objetivo",
        placeholder="https://objetivo.local",
        help="Incluye http:// o https://",
    )
    nombre = st.text_input("Nombre del objetivo", value="Auditoria")

    st.divider()
    st.subheader("Modulos a ejecutar")

    # Boton para marcar/desmarcar todos.
    col_a, col_b = st.columns(2)
    if col_a.button("Marcar todos", use_container_width=True):
        for clave in MODULOS_INFO:
            st.session_state[f"mod_{clave}"] = True
    if col_b.button("Desmarcar todos", use_container_width=True):
        for clave in MODULOS_INFO:
            st.session_state[f"mod_{clave}"] = False

    modulos_activos = {}
    for clave, (titulo, desc) in MODULOS_INFO.items():
        # Por defecto activamos los ligeros; los pesados (zap, nmap, sqlmap,
        # agente_ia) no.
        default = clave not in ("zap", "nmap", "sqlmap", "puertos_nmap", "agente_ia")
        modulos_activos[clave] = st.checkbox(
            titulo, value=st.session_state.get(f"mod_{clave}", default),
            key=f"mod_{clave}", help=desc,
        )

    st.divider()
    st.subheader("Opciones avanzadas")
    verificar_ssl = st.checkbox("Verificar certificado SSL", value=True,
                                help="Desactivar para certificados autofirmados.")
    ruta_zap = st.text_input(
        "Ruta a zap.sh (si usas ZAP)",
        value=os.path.expanduser("~/proyectos/ZAP_2.17.0/zap.sh"),
    )

    # --- Configuracion del agente de IA (solo si esta activado) ---
    gemini_api_key = ""
    limite_acciones_agente = 20
    timeout_agente = 600
    if modulos_activos.get("agente_ia"):
        st.divider()
        st.subheader("Agente de IA (Gemini)")
        gemini_api_key = st.text_input(
            "API key de Gemini",
            value=os.environ.get("GEMINI_API_KEY", ""),
            type="password",
            help="Se puede dejar vacio si GEMINI_API_KEY ya esta en el entorno.",
        )
        limite_acciones_agente = st.number_input(
            "Limite de acciones por sesion", min_value=1, max_value=50,
            value=20,
        )
        timeout_agente = st.number_input(
            "Timeout de sesion (segundos)", min_value=60, max_value=1800,
            value=600, step=60,
        )
        st.caption(
            "El agente solo puede actuar dentro del dominio del objetivo, "
            "no ejecuta metodos destructivos y se detiene al llegar al "
            "limite de acciones o al timeout, lo que ocurra primero."
        )

    st.divider()
    autorizado = st.checkbox(
        "Confirmo que tengo AUTORIZACION para auditar este objetivo",
        value=False,
    )

    lanzar = st.button("Iniciar auditoria", type="primary",
                       use_container_width=True, disabled=not autorizado)


# --- Zona principal ---
if not url:
    st.info("Introduce una URL objetivo en la barra lateral para comenzar.")
    st.stop()

if lanzar:
    # Validaciones basicas.
    if not (url.startswith("http://") or url.startswith("https://")):
        st.error("La URL debe empezar por http:// o https://")
        st.stop()
    if not autorizado:
        st.error("Debes confirmar la autorizacion para auditar.")
        st.stop()

    # Construir la configuracion a partir de la interfaz.
    config = {
        "objetivo": {
            "url": url, "nombre": nombre, "autorizacion_confirmada": True,
        },
        "modulos": modulos_activos,
        "opciones": {
            "timeout": 10, "verificar_ssl": verificar_ssl,
            "user_agent": "AuditoriaWeb/1.0 (GUI)",
        },
        "salida": {"carpeta": "resultados"},
        "nuclei": {"severidades": "medium,high,critical", "timeout": 300},
        "nmap": {"top_ports": 1000, "timeout": 300},
        "zap": {"ruta": ruta_zap, "active_scan": True,
                "timeout_spider": 300, "timeout_ascan": 900},
        "crawler": {"max_paginas": 50, "max_profundidad": 3},
        "sqlmap": {"urls": [], "level": 1, "risk": 1, "timeout": 180},
        "agente_ia": {
            "activo": modulos_activos.get("agente_ia", False),
            "api_key": gemini_api_key,
            "modelo": "gemini-2.5-flash",
            "limite_acciones": limite_acciones_agente,
            "timeout_sesion_seg": timeout_agente,
        },
    }

    logger = configurar_logger()

    # Barra de progreso y estado.
    barra = st.progress(0, text="Preparando auditoria...")
    estado = st.empty()

    def callback(indice, total, nombre_modulo):
        pct = int(indice / max(total, 1) * 100)
        barra.progress(pct, text=f"Ejecutando: {nombre_modulo} ({indice}/{total})")
        estado.info(f"En curso: **{nombre_modulo}**")

    # Ejecutar la auditoria.
    with st.spinner("Auditoria en curso... esto puede tardar varios minutos."):
        reporte = ejecutar_auditoria(config, logger, callback_progreso=callback)

    barra.progress(100, text="Auditoria completada.")
    estado.success("Auditoria completada.")

    datos = reporte.construir()

    # Guardar en session_state para que persista al re-renderizar.
    st.session_state["datos_reporte"] = datos

    # Generar los informes.
    carpeta = "resultados"
    reporte.guardar_json(carpeta)
    rutas = generar_informe(datos, carpeta, ["html", "pdf"], logger)
    st.session_state["rutas_informe"] = rutas


# --- Mostrar resultados (si existen) ---
if "datos_reporte" in st.session_state:
    datos = st.session_state["datos_reporte"]
    meta = datos["metadatos"]
    analisis = datos.get("analisis_riesgo", {})
    valoracion = analisis.get("valoracion_global", {})

    st.divider()
    st.header("Resultados")

    # --- Metricas principales ---
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total hallazgos", meta["total_hallazgos"])
    if valoracion:
        c2.metric("Riesgo global", valoracion.get("nivel", "-"),
                  f"{valoracion.get('puntuacion', 0)}/10")
    resumen = datos["resumen_por_severidad"]
    c3.metric("Criticos + Altos", resumen.get("critica", 0) + resumen.get("alta", 0))
    c4.metric("Duracion", f"{meta['duracion_segundos']:.0f}s")

    # --- Valoracion global destacada ---
    if valoracion:
        color = COLOR_NIVEL.get(valoracion.get("nivel"), "#607D8B")
        st.markdown(
            f"<div style='background:{color};color:white;padding:20px;"
            f"border-radius:8px;text-align:center;'>"
            f"<span style='font-size:36px;font-weight:bold;'>"
            f"{valoracion.get('puntuacion')}/10</span><br>"
            f"<span style='font-size:18px;'>Riesgo {valoracion.get('nivel','')}</span>"
            f"</div>",
            unsafe_allow_html=True,
        )
        st.write(valoracion.get("descripcion", ""))

    # --- Distribucion por severidad ---
    st.subheader("Distribucion por severidad")
    cols = st.columns(5)
    for col, (sev, cant) in zip(cols, resumen.items()):
        col.markdown(
            f"<div style='background:{COLOR_SEV[sev]};color:white;padding:12px;"
            f"border-radius:6px;text-align:center;'>"
            f"<span style='font-size:24px;font-weight:bold;'>{cant}</span><br>"
            f"<span style='font-size:12px;'>{sev.capitalize()}</span></div>",
            unsafe_allow_html=True,
        )

    # --- Matriz de riesgo ---
    matriz = analisis.get("matriz")
    if matriz:
        st.subheader("Matriz de riesgo (Impacto x Probabilidad)")
        # Construir la matriz como HTML.
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

    # --- Hallazgos ---
    st.subheader("Hallazgos")
    # Agrupar por categoria.
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
                    f"</span> **{h['titulo']}**{cvss}",
                    unsafe_allow_html=True,
                )
                st.write(h["descripcion"])
                if h.get("evidencia"):
                    st.code(h["evidencia"], language=None)
                if h.get("recomendacion"):
                    st.caption(f"Recomendacion: {h['recomendacion']}")
                st.divider()

    # --- Descargas ---
    st.subheader("Descargar informe")
    if "rutas_informe" in st.session_state:
        cols = st.columns(len(st.session_state["rutas_informe"]) + 1)
        # JSON siempre.
        import json
        cols[0].download_button(
            "Descargar JSON",
            data=json.dumps(datos, ensure_ascii=False, indent=2),
            file_name="informe.json", mime="application/json",
        )
        # HTML y PDF.
        for i, ruta in enumerate(st.session_state["rutas_informe"], 1):
            if os.path.isfile(ruta):
                with open(ruta, "rb") as f:
                    ext = ruta.rsplit(".", 1)[-1].upper()
                    cols[i].download_button(
                        f"Descargar {ext}", data=f.read(),
                        file_name=os.path.basename(ruta),
                    )