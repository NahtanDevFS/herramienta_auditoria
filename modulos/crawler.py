"""
crawler.py  (modulo de reconocimiento - Recon / base para A05)

Rastrea el sitio objetivo para descubrir rutas, formularios y parametros.
AHORA renderiza JavaScript con Playwright (motor de navegador real), de modo
que funciona con aplicaciones de una sola pagina (SPAs: Angular, React, Vue),
donde el HTML crudo esta vacio y todo lo pinta el navegador. Si Playwright no
esta disponible, cae a un rastreo HTTP clasico (requests + BeautifulSoup).

Valor:
  1. Hallazgos informativos: mapa del sitio, formularios y URLs con parametros.
  2. Lista de URLs con parametros para sqlmap (archivo urls_con_parametros.txt).
  3. Un MAPA ESTRUCTURADO (config["_mapa_sitio"]) que el agente de IA usa como
     contexto: paginas concretas con login, buscador o parametros, para que
     razone sobre una superficie real en vez de explorar a ciegas.

Patron de siempre:  def ejecutar(config, logger) -> list[Hallazgo]
"""

import logging
import os
import time
from collections import deque
from urllib.parse import urljoin, urlparse, urldefrag, urlunparse

from core.modelo_hallazgo import Hallazgo

ORIGEN = "modulo_crawler"

MAX_PAGINAS_DEFECTO = 50
MAX_PROFUNDIDAD_DEFECTO = 3
PAUSA_ENTRE_PETICIONES = 0.2

EXTENSIONES_IGNORAR = {
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".webp",
    ".css", ".js", ".pdf", ".zip", ".tar", ".gz", ".mp4", ".mp3",
    ".woff", ".woff2", ".ttf", ".eot",
}

# Rutas comunes que un pentester prueba en CUALQUIER sitio (no es conocimiento
# especifico del objetivo). Incluye variantes hash para SPAs.
RUTAS_COMUNES = [
    "/login", "/signin", "/admin", "/administrator", "/administration",
    "/search", "/account", "/user", "/dashboard", "/register", "/api",
    "/#/login", "/#/search", "/#/administration", "/#/register", "/#/basket",
]

# JS que extrae la superficie de la pagina YA RENDERIZADA.
JS_EXTRAER = """
() => {
  const abs = (h) => { try { return new URL(h, location.href).href; } catch(e){ return ''; } };
  const forms = [...document.querySelectorAll('form')].slice(0,20).map(f => {
    const campos = [...f.querySelectorAll('input,textarea,select')]
      .map(el => ({nombre: el.name||el.id||el.getAttribute('placeholder')||'',
                   tipo: (el.type||el.tagName||'').toLowerCase()}))
      .filter(c => c.tipo!=='hidden' && c.tipo!=='submit' && c.tipo!=='button');
    return {accion: abs(f.getAttribute('action')||location.href),
            metodo: (f.getAttribute('method')||'get').toUpperCase(),
            tiene_password: campos.some(c => c.tipo==='password'),
            campos: campos.slice(0,10)};
  });
  const buscadores = [...document.querySelectorAll('input')].filter(el => {
    const t=(el.type||'').toLowerCase();
    const n=((el.name||'')+(el.id||'')+(el.getAttribute('placeholder')||'')).toLowerCase();
    return t==='search' || /search|buscar|query|\\bq\\b/.test(n);
  }).length;
  let enlaces = [...document.querySelectorAll('a[href]')].map(a => a.href);
  const rls = [...document.querySelectorAll('[routerlink]')]
    .map(a => abs(a.getAttribute('routerlink')));
  enlaces = [...new Set(enlaces.concat(rls))].filter(Boolean).slice(0,120);
  return {forms, buscadores, enlaces};
}
"""


def ejecutar(config: dict, logger: logging.Logger) -> list[Hallazgo]:
    objetivo = config["objetivo"]["url"].strip()
    conf_crawler = config.get("crawler", {})
    max_paginas = conf_crawler.get("max_paginas", MAX_PAGINAS_DEFECTO)
    max_profundidad = conf_crawler.get("max_profundidad", MAX_PROFUNDIDAD_DEFECTO)
    render_js = conf_crawler.get("render_js", True)

    dominio = urlparse(objetivo).netloc

    logger.info(f"[crawler] Iniciando rastreo de {objetivo} "
                f"(max {max_paginas} paginas, profundidad {max_profundidad})")

    datos = None
    if render_js:
        try:
            datos = _rastrear_con_navegador(objetivo, dominio, max_paginas,
                                            max_profundidad, logger)
        except ImportError:
            logger.warning("[crawler] Playwright no disponible; rastreo HTTP clasico "
                           "(en SPAs vera poco). Instalar: pip install playwright")
        except Exception as e:
            logger.warning(f"[crawler] Fallo el rastreo con navegador ({e}); "
                           f"se usa el rastreo HTTP clasico.")

    if datos is None:
        datos = _rastrear_con_http(objetivo, dominio, max_paginas,
                                   max_profundidad, config, logger)

    visitadas, rutas, urls_param, formularios, mapa = datos

    logger.info(f"[crawler] Rastreo terminado. {len(visitadas)} pagina(s), "
                f"{len(formularios)} formulario(s), "
                f"{len(urls_param)} URL(s) con parametros, "
                f"{len(mapa)} pagina(s) con superficie de ataque.")

    _guardar_urls_para_sqlmap(urls_param, config, logger)

    # Dejar el mapa estructurado para el agente de IA (config es compartido).
    config["_mapa_sitio"] = mapa

    return _construir_hallazgos(objetivo, rutas, formularios, urls_param, logger)


# ---------------------------------------------------------------------------
# Rastreo con navegador (renderiza JS) — el importante para SPAs
# ---------------------------------------------------------------------------
def _rastrear_con_navegador(objetivo, dominio, max_paginas, max_prof, logger):
    from playwright.sync_api import sync_playwright

    visitadas, rutas, urls_param = set(), set(), set()
    formularios, firmas, mapa = [], set(), []

    origen = _origen(objetivo)
    cola = deque([(objetivo, 0)])
    for rc in RUTAS_COMUNES:                       # sembrar rutas comunes
        cola.append((urljoin(origen + "/", rc.lstrip("/")) if not rc.startswith("/#")
                     else origen + rc, 1))

    pw = sync_playwright().start()
    browser = pw.chromium.launch(headless=True)
    ctx = browser.new_context(ignore_https_errors=True,
                              viewport={"width": 1280, "height": 800})
    page = ctx.new_page()
    page.set_default_timeout(8000)
    try:
        while cola and len(visitadas) < max_paginas:
            url, prof = cola.popleft()
            if url in visitadas or prof > max_prof:
                continue
            try:
                try:
                    resp = page.goto(url, wait_until="networkidle", timeout=12000)
                except Exception:
                    resp = page.goto(url, wait_until="domcontentloaded")
                page.wait_for_timeout(1000)
                _descartar_overlays(page)
            except Exception as e:
                logger.debug(f"[crawler] no se pudo abrir {url}: {e}")
                continue

            visitadas.add(url)
            # Descartar 404 de rutas comunes que no existen (evita ruido).
            estado = getattr(resp, "status", 200) if resp else 200
            if estado >= 400:
                continue

            url_real = page.url
            rutas.add(url_real)
            if urlparse(url_real).query:
                urls_param.add(url_real)

            try:
                info = page.evaluate(JS_EXTRAER)
            except Exception:
                continue

            hay_login = False
            for f in info.get("forms", []):
                if f.get("tiene_password"):
                    hay_login = True
                firma = (f.get("accion"), tuple(c["nombre"] for c in f.get("campos", [])))
                if firma not in firmas:
                    firmas.add(firma)
                    formularios.append({
                        "pagina": url_real, "action": f.get("accion"),
                        "metodo": f.get("metodo"), "campos": f.get("campos", []),
                    })
            hay_busqueda = info.get("buscadores", 0) > 0

            for enlace in info.get("enlaces", []):
                enlace_limpio = enlace
                if urlparse(enlace_limpio).netloc != dominio:
                    continue
                if _tiene_extension_ignorada(enlace_limpio):
                    continue
                if urlparse(enlace_limpio).query:
                    urls_param.add(enlace_limpio)
                if enlace_limpio not in visitadas:
                    cola.append((enlace_limpio, prof + 1))

            # Registrar la pagina en el mapa si tiene superficie de ataque.
            if hay_login or hay_busqueda or urlparse(url_real).query:
                mapa.append({
                    "url": url_real,
                    "tiene_login": hay_login,
                    "tiene_busqueda": hay_busqueda,
                    "tiene_parametros": bool(urlparse(url_real).query),
                })
            time.sleep(PAUSA_ENTRE_PETICIONES)
    finally:
        for cerrar in (ctx.close, browser.close, pw.stop):
            try:
                cerrar()
            except Exception:
                pass

    # Compactar el mapa (el agente digiere mejor algo corto).
    mapa = _compactar_mapa(mapa)
    return visitadas, rutas, urls_param, formularios, mapa


# ---------------------------------------------------------------------------
# Rastreo HTTP clasico (fallback, para sitios no-SPA o sin Playwright)
# ---------------------------------------------------------------------------
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

    return visitadas, rutas, urls_param, formularios, _compactar_mapa(mapa)


# ---------------------------------------------------------------------------
# Auxiliares
# ---------------------------------------------------------------------------
def _origen(url):
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, "", "", "", ""))


def _compactar_mapa(mapa, maximo=15):
    """Deduplica por URL y prioriza login/busqueda; cap para no saturar al 7B."""
    vistos, salida = set(), []
    for e in sorted(mapa, key=lambda x: (not x["tiene_login"], not x["tiene_busqueda"])):
        if e["url"] in vistos:
            continue
        vistos.add(e["url"])
        salida.append(e)
        if len(salida) >= maximo:
            break
    return salida


def _descartar_overlays(page):
    for sel in ["button[aria-label='Close Welcome Banner']",
                "a[aria-label='dismiss cookie message']",
                "button:has-text('Dismiss')", "button:has-text('Accept')",
                "button:has-text('Aceptar')", "button:has-text('OK')"]:
        try:
            loc = page.locator(sel).first
            if loc.count() > 0 and loc.is_visible():
                loc.click(timeout=1200)
        except Exception:
            continue


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
            titulo=f"Mapa del sitio: {len(rutas)} ruta(s) descubierta(s)",
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