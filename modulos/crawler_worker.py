"""
crawler_worker.py  —  Worker de rastreo con navegador (se ejecuta en SUBPROCESO)

Playwright (API sincrona) NO puede correr dentro del bucle de asyncio de
Streamlit. Para evitar ese conflicto, todo el rastreo con navegador se ejecuta
aqui, en un proceso APARTE y limpio, lanzado por crawler.py.

Uso (lo invoca crawler.py, no se corre a mano normalmente):
    python -m modulos.crawler_worker <url_objetivo> <max_paginas> <max_prof> <salida_json>

Escribe en <salida_json> un objeto con: rutas, urls_param, formularios, mapa.
"""

import json
import sys
import time
from collections import deque
from urllib.parse import urljoin, urlparse, urlunparse

RUTAS_COMUNES = [
    "/login", "/signin", "/admin", "/administrator", "/administration",
    "/search", "/account", "/user", "/dashboard", "/register", "/api",
    "/#/login", "/#/search", "/#/administration", "/#/register", "/#/basket",
]

EXTENSIONES_IGNORAR = {
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".webp",
    ".css", ".js", ".pdf", ".zip", ".tar", ".gz", ".mp4", ".mp3",
    ".woff", ".woff2", ".ttf", ".eot",
}

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


def _origen(url):
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, "", "", "", ""))


def _tiene_extension_ignorada(url):
    ruta = urlparse(url).path.lower()
    return any(ruta.endswith(ext) for ext in EXTENSIONES_IGNORAR)


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


def _compactar_mapa(mapa, maximo=15):
    vistos, salida = set(), []
    for e in sorted(mapa, key=lambda x: (not x["tiene_login"], not x["tiene_busqueda"])):
        if e["url"] in vistos:
            continue
        vistos.add(e["url"])
        salida.append(e)
        if len(salida) >= maximo:
            break
    return salida


def rastrear(objetivo, max_paginas, max_prof):
    from playwright.sync_api import sync_playwright

    dominio = urlparse(objetivo).netloc
    visitadas, rutas, urls_param = set(), set(), set()
    formularios, firmas, mapa = [], set(), []

    origen = _origen(objetivo)
    cola = deque([(objetivo, 0)])
    for rc in RUTAS_COMUNES:
        destino = (origen + rc) if rc.startswith("/#") else urljoin(origen + "/", rc.lstrip("/"))
        cola.append((destino, 1))

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
            except Exception:
                continue

            visitadas.add(url)
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
                if urlparse(enlace).netloc != dominio:
                    continue
                if _tiene_extension_ignorada(enlace):
                    continue
                if urlparse(enlace).query:
                    urls_param.add(enlace)
                if enlace not in visitadas:
                    cola.append((enlace, prof + 1))

            if hay_login or hay_busqueda or urlparse(url_real).query:
                mapa.append({"url": url_real, "tiene_login": hay_login,
                             "tiene_busqueda": hay_busqueda,
                             "tiene_parametros": bool(urlparse(url_real).query)})
            time.sleep(0.2)
    finally:
        for cerrar in (ctx.close, browser.close, pw.stop):
            try:
                cerrar()
            except Exception:
                pass

    return {
        "rutas": sorted(rutas),
        "urls_param": sorted(urls_param),
        "formularios": formularios,
        "mapa": _compactar_mapa(mapa),
    }


def main():
    if len(sys.argv) < 5:
        print("uso: python -m modulos.crawler_worker <url> <max_paginas> <max_prof> <salida_json>",
              file=sys.stderr)
        sys.exit(2)
    objetivo = sys.argv[1]
    max_paginas = int(sys.argv[2])
    max_prof = int(sys.argv[3])
    salida = sys.argv[4]
    try:
        resultado = rastrear(objetivo, max_paginas, max_prof)
        with open(salida, "w", encoding="utf-8") as f:
            json.dump(resultado, f, ensure_ascii=False)
    except Exception as e:
        # Escribir el error para que el proceso padre sepa que fallo.
        with open(salida, "w", encoding="utf-8") as f:
            json.dump({"error": str(e)}, f, ensure_ascii=False)
        sys.exit(1)


if __name__ == "__main__":
    main()