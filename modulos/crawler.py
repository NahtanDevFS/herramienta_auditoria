# crawler py modulo de reconocimiento (recon / base para a05)
# rastrea el sitio objetivo para descubrir rutas, formularios y parametros
# usa playwright (en un subproceso aislado) para renderizar js, con un fallback a HTTP puro

import json
import logging
import os
import subprocess
import sys
import tempfile
import time
from collections import deque
from urllib.parse import urljoin, urlparse, urldefrag

from core.modelo_hallazgo import Hallazgo

ORIGEN = "modulo_crawler"

MAX_PAGINAS_DEFECTO = 50
MAX_PROFUNDIDAD_DEFECTO = 3
PAUSA_ENTRE_PETICIONES = 0.2
TIMEOUT_WORKER_SEG = 300

EXTENSIONES_IGNORAR = {
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".webp",
    ".css", ".js", ".pdf", ".zip", ".tar", ".gz", ".mp4", ".mp3",
    ".woff", ".woff2", ".ttf", ".eot",
}


def ejecutar(config: dict, logger: logging.Logger) -> list[Hallazgo]:
    objetivo = config["objetivo"]["url"].strip()
    conf_crawler = config.get("crawler", {})
    max_paginas = conf_crawler.get("max_paginas", MAX_PAGINAS_DEFECTO)
    max_profundidad = conf_crawler.get("max_profundidad", MAX_PROFUNDIDAD_DEFECTO)
    render_js = conf_crawler.get("render_js", True)

    # credenciales (si las hay): permiten rastrear tambien la zona autenticada, y
    # asi descubrir rutas reales que no son visibles sin iniciar sesion (el login
    # no enlaza a la zona privada) sin esto, en un spa solo se ve el login
    agente_cfg = config.get("agente_ia", {}) or {}
    aut_cfg = config.get("autenticacion", {}) or {}
    usuario = agente_cfg.get("usuario") or aut_cfg.get("usuario")
    contrasena = agente_cfg.get("contrasena") or aut_cfg.get("contrasena")

    dominio = urlparse(objetivo).netloc
    logger.info(f"[crawler] Iniciando rastreo de {objetivo} "
                f"(max {max_paginas} paginas, profundidad {max_profundidad})")

    datos = None
    if render_js:
        datos = _rastrear_con_subproceso(objetivo, max_paginas, max_profundidad,
                                         logger, usuario, contrasena)

    if datos is None:
        logger.info("[crawler] Usando rastreo HTTP clasico (sin render de JS).")
        datos = _rastrear_con_http(objetivo, dominio, max_paginas,
                                   max_profundidad, config, logger)

    rutas = set(datos.get("rutas", []))
    urls_param = set(datos.get("urls_param", []))
    formularios = datos.get("formularios", [])
    mapa = datos.get("mapa", [])
    endpoints_api = datos.get("endpoints_api", [])

    logger.info(f"[crawler] Rastreo terminado. {len(rutas)} ruta(s), "
                f"{len(formularios)} formulario(s), {len(urls_param)} URL(s) con "
                f"parametros, {len(mapa)} pagina(s) con superficie de ataque.")

    _guardar_urls_para_sqlmap(urls_param, config, logger)
    config["_mapa_sitio"] = mapa   # config es compartido > lo lee el agente
    config["_rutas_descubiertas"] = sorted(rutas)  # para sembrar objetivos estables
    config["_endpoints_api"] = endpoints_api       # endpoints rest para el agente
    if endpoints_api:
        logger.info(f"[crawler] {len(endpoints_api)} endpoint(s) de API detectado(s).")

    return _construir_hallazgos(objetivo, rutas, formularios, urls_param, logger)


# rastreo con navegador (subproceso aislado)
def _rastrear_con_subproceso(objetivo, max_paginas, max_prof, logger,
                             usuario=None, contrasena=None):
    tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
    tmp.close()
    salida_json = tmp.name
    try:
        cmd = [sys.executable, "-m", "modulos.crawler_worker",
               objetivo, str(max_paginas), str(max_prof), salida_json]
        # las credenciales se pasan por variables de entorno (no por argv, que es
        # visible en la lista de procesos)
        env = os.environ.copy()
        if usuario:
            env["CRAWLER_USER"] = usuario
        if contrasena:
            env["CRAWLER_PASS"] = contrasena
        if usuario and contrasena:
            logger.info("[crawler] Rastreo AUTENTICADO: se intentara iniciar sesion "
                        "antes de mapear, para descubrir la zona privada.")
        logger.info("[crawler] Lanzando rastreo con navegador en subproceso...")
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=TIMEOUT_WORKER_SEG, env=env)
        if proc.returncode != 0:
            detalle = (proc.stderr or "").strip().splitlines()[-1:] or ["sin detalle"]
            logger.warning(f"[crawler] El subproceso del navegador fallo: {detalle[0]}")

        with open(salida_json, encoding="utf-8") as f:
            datos = json.load(f)
        if "error" in datos:
            logger.warning(f"[crawler] Worker reporto error: {datos['error']}")
            return None
        return datos
    except subprocess.TimeoutExpired:
        logger.warning(f"[crawler] El rastreo con navegador supero {TIMEOUT_WORKER_SEG}s. "
                       f"Se usa el rastreo HTTP.")
        return None
    except Exception as e:
        logger.warning(f"[crawler] No se pudo ejecutar el subproceso del navegador: {e}")
        return None
    finally:
        try:
            os.unlink(salida_json)
        except OSError:
            pass


# rastreo HTTP clasico (fallback)
def _rastrear_con_http(objetivo, dominio, max_paginas, max_prof, config, logger):
    import requests
    from bs4 import BeautifulSoup

    opciones = config.get("opciones", {})
    timeout = opciones.get("timeout", 10)
    verificar_ssl = opciones.get("verificar_ssl", True)
    user_agent = opciones.get("user_agent", "AuditoriaWeb/1.0")

    visitadas, rutas, urls_param = set(), set(), set()
    formularios, firmas, mapa = [], set(), []
    cola = deque([(objetivo, 0)])
    sesion = requests.Session()
    sesion.headers.update({"User-Agent": user_agent})

    while cola and len(visitadas) < max_paginas:
        url, prof = cola.popleft()
        url, _ = urldefrag(url)
        if url in visitadas or prof > max_prof:
            continue
        try:
            resp = sesion.get(url, timeout=timeout, verify=verificar_ssl,
                              allow_redirects=True)
        except requests.exceptions.RequestException:
            continue
        visitadas.add(url)
        rutas.add(url)
        if urlparse(url).query:
            urls_param.add(url)
        if "text/html" not in resp.headers.get("Content-Type", ""):
            continue
        try:
            sopa = BeautifulSoup(resp.text, "html.parser")
        except Exception:
            continue
        hay_login = False
        for form in sopa.find_all("form"):
            datos_form = _extraer_formulario_bs(form, url)
            if datos_form:
                if any(c["tipo"] == "password" for c in datos_form["campos"]):
                    hay_login = True
                firma = (datos_form["action"],
                         tuple(c["nombre"] for c in datos_form["campos"]))
                if firma not in firmas:
                    firmas.add(firma)
                    formularios.append(datos_form)
        for a in sopa.find_all("a", href=True):
            enlace = urljoin(url, a["href"])
            enlace, _ = urldefrag(enlace)
            if urlparse(enlace).netloc != dominio or _tiene_extension_ignorada(enlace):
                continue
            if urlparse(enlace).query:
                urls_param.add(enlace)
            if enlace not in visitadas:
                cola.append((enlace, prof + 1))
        if hay_login or urlparse(url).query:
            mapa.append({"url": url, "tiene_login": hay_login,
                         "tiene_busqueda": False,
                         "tiene_parametros": bool(urlparse(url).query)})
        time.sleep(PAUSA_ENTRE_PETICIONES)

    return {"rutas": sorted(rutas), "urls_param": sorted(urls_param),
            "formularios": formularios, "mapa": mapa}


# auxiliares
def _extraer_formulario_bs(form, url_pagina):
    action = form.get("action", "")
    metodo = form.get("method", "get").upper()
    action_completa = urljoin(url_pagina, action) if action else url_pagina
    campos = []
    for el in form.find_all(["input", "textarea", "select"]):
        nombre = el.get("name")
        tipo = el.get("type", "text")
        if nombre:
            campos.append({"nombre": nombre, "tipo": tipo})
    if not campos:
        return None
    return {"pagina": url_pagina, "action": action_completa,
            "metodo": metodo, "campos": campos}


def _tiene_extension_ignorada(url):
    ruta = urlparse(url).path.lower()
    return any(ruta.endswith(ext) for ext in EXTENSIONES_IGNORAR)


def _guardar_urls_para_sqlmap(urls, config, logger):
    if not urls:
        return
    carpeta = config.get("salida", {}).get("carpeta", "resultados")
    os.makedirs(carpeta, exist_ok=True)
    ruta = os.path.join(carpeta, "urls_con_parametros.txt")
    try:
        with open(ruta, "w", encoding="utf-8") as f:
            for url in sorted(urls):
                f.write(url + "\n")
        logger.info(f"[crawler] {len(urls)} URL(s) con parametros guardadas en {ruta}.")
    except OSError as e:
        logger.warning(f"[crawler] No se pudieron guardar las URLs: {e}")


def _construir_hallazgos(objetivo, rutas, formularios, urls_param, logger):
    hallazgos = []
    if rutas:
        paths = sorted({urlparse(r).path or urlparse(r).fragment or "/" for r in rutas})
        muestra = paths[:40]
        resumen = ", ".join(muestra)
        if len(paths) > 40:
            resumen += f" ... (+{len(paths) - 40} mas)"
        hallazgos.append(Hallazgo(
            # el conteo debe coincidir con las rutas realmente listadas (paths
            # unicos), no con el total de urls crudas (que incluye duplicados por
            # query/fragment) antes decia n pero listaba menos
            titulo=f"Mapa del sitio: {len(paths)} ruta(s) descubierta(s)",
            categoria="A05", severidad="informativa", cvss=None,
            descripcion="Inventario de rutas descubiertas durante el rastreo (con "
                        "renderizado de JavaScript). Parte del reconocimiento.",
            evidencia=f"Rutas: {resumen}",
            recomendacion="Revisar que no haya rutas sensibles o de administracion "
                          "accesibles sin autenticacion.",
            herramienta_origen=ORIGEN, url_afectada=objetivo))
    if formularios:
        lineas = []
        for f in formularios[:15]:
            nombres = ", ".join(c["nombre"] for c in f["campos"])
            lineas.append(f"{f['metodo']} {f['action']} [campos: {nombres}]")
        resumen = " ; ".join(lineas)
        if len(formularios) > 15:
            resumen += f" ... (+{len(formularios) - 15} mas)"
        hallazgos.append(Hallazgo(
            titulo=f"Formularios detectados: {len(formularios)}",
            categoria="A05", severidad="informativa", cvss=None,
            descripcion="Formularios encontrados en el sitio. Son puntos de entrada de "
                        "datos y posibles vectores de inyeccion (SQLi, XSS).",
            evidencia=resumen,
            recomendacion="Validar y sanitizar toda entrada en el servidor. Verificar CSRF.",
            herramienta_origen=ORIGEN, url_afectada=objetivo))
    if urls_param:
        muestra = sorted(urls_param)[:20]
        resumen = "; ".join(muestra)
        if len(urls_param) > 20:
            resumen += f" ... (+{len(urls_param) - 20} mas)"
        hallazgos.append(Hallazgo(
            titulo=f"URLs con parametros: {len(urls_param)}",
            categoria="A05", severidad="informativa", cvss=None,
            descripcion="URLs con parametros de entrada. Candidatos para pruebas de "
                        "inyeccion. Guardadas para sqlmap.",
            evidencia=f"URLs: {resumen}",
            recomendacion="Validar los parametros y usar consultas parametrizadas.",
            herramienta_origen=ORIGEN, url_afectada=objetivo))
    logger.info(f"[crawler] {len(hallazgos)} hallazgo(s) informativo(s) generado(s).")
    return hallazgos