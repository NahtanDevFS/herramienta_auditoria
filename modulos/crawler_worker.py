# worker aislado para rastreo visual (playwright no soporta el bucle de streamlit)

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


def _ruta_spa(url):
    # identidad de vista: el fragmento en spas o el path en sitios clasicos
    p = urlparse(url)
    return p.fragment or p.path or "/"


def _iniciar_sesion(page, objetivo, usuario, contrasena):
    # inicia sesion antes de mapear para descubrir rutas exclusivas de la zona privada
    origen = _origen(objetivo)
    candidatos = [objetivo] + [origen + r for r in
                               ("/login", "/signin", "/admin", "/#/login")]
    for cand in candidatos:
        try:
            page.goto(cand, wait_until="domcontentloaded")
            page.wait_for_timeout(1000)
            _descartar_overlays(page)
            u = page.locator("input[type=email], input[name*=user i], "
                             "input[id*=user i], input[type=text]").first
            p = page.locator("input[type=password]").first
            if u.count() == 0 or p.count() == 0 or not p.is_visible():
                continue
            u.fill(usuario)
            p.fill(contrasena)
            btn = page.locator("button[type=submit], #loginButton, "
                               "button:has-text('Entrar'), button:has-text('Iniciar'), "
                               "button:has-text('Login'), button:has-text('Log in')").first
            if btn.count() > 0:
                try:
                    btn.click()
                except Exception:
                    p.press("Enter")
            else:
                p.press("Enter")
            page.wait_for_timeout(1800)
            hay_pass = page.locator("input[type=password]").count() > 0
            tok = page.evaluate(
                "() => { try { for (let i=0;i<localStorage.length;i++){"
                "const v=localStorage.getItem(localStorage.key(i))||''; "
                "if(v.length>20) return true;} } catch(e){} return false; }")
            if (not hay_pass) or tok:
                return True
        except Exception:
            continue
    return False


def _compactar_mapa(mapa, maximo=15):
    # deduplica vistas de spa priorizando aquellas con login o formularios
    vistos, salida = set(), []
    for e in sorted(mapa, key=lambda x: (not x["tiene_login"], not x["tiene_busqueda"],
                                         not x.get("tiene_formulario", False))):
        clave = _ruta_spa(e["url"])
        if clave in vistos:
            continue
        vistos.add(clave)
        salida.append(e)
        if len(salida) >= maximo:
            break
    return salida


def rastrear(objetivo, max_paginas, max_prof, usuario=None, contrasena=None):
    from playwright.sync_api import sync_playwright

    dominio = urlparse(objetivo).netloc
    visitadas, rutas, urls_param = set(), set(), set()
    formularios, firmas, mapa = [], set(), []
    endpoints_api = set()   # endpoints rest detectados escuchando la red

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

    # intercepta fetch/xhr en background para mapear endpoints de api reales
    def _capturar_peticion(req):
        try:
            u = req.url
            if urlparse(u).netloc != dominio:
                return
            ruta = urlparse(u).path.lower()
            if "/api/" in ruta or "/rest/" in ruta or ruta.endswith("/api") \
               or ruta.endswith("/rest") or "/graphql" in ruta:
                endpoints_api.add(u.split("#")[0])
        except Exception:
            pass

    page.on("request", _capturar_peticion)

    # si hay credenciales, autentica primero para que el dom revele las rutas privadas
    if usuario and contrasena:
        try:
            if _iniciar_sesion(page, objetivo, usuario, contrasena):
                print("[crawler_worker] Sesion iniciada; se rastreara la zona "
                      "autenticada.", file=sys.stderr)
            else:
                print("[crawler_worker] No se pudo iniciar sesion; rastreo anonimo.",
                      file=sys.stderr)
        except Exception:
            pass

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
            hay_formulario = False
            TEXTO = {"text", "email", "textarea", "tel", "search", "number", "url", ""}
            for f in info.get("forms", []):
                if f.get("tiene_password"):
                    hay_login = True
                elif any(c.get("tipo") in TEXTO for c in f.get("campos", [])):
                    # formulario de datos sin password: contacto, feedback, perfil
                    hay_formulario = True
                firma = (_ruta_spa(url_real),
                         tuple(c["nombre"] for c in f.get("campos", [])))
                if firma not in firmas:
                    firmas.add(firma)
                    formularios.append({
                        "pagina": url_real, "action": f.get("accion"),
                        "metodo": f.get("metodo"), "campos": f.get("campos", []),
                    })
            hay_busqueda = info.get("buscadores", 0) > 0

            # ejecuta busqueda de prueba para que el listener capture la llamada a la api
            if hay_busqueda:
                try:
                    campo = page.locator(
                        "input[type=search], input[name*=search i], "
                        "input[id*=search i], input[name=q]").first
                    if campo.count() > 0 and campo.is_visible():
                        campo.fill("test")
                        campo.press("Enter")
                        page.wait_for_timeout(1200)  # deja que la API responda
                except Exception:
                    pass

            for enlace in info.get("enlaces", []):
                if urlparse(enlace).netloc != dominio:
                    continue
                if _tiene_extension_ignorada(enlace):
                    continue
                if urlparse(enlace).query:
                    urls_param.add(enlace)
                if enlace not in visitadas:
                    cola.append((enlace, prof + 1))

            if hay_login or hay_busqueda or hay_formulario or urlparse(url_real).query:
                mapa.append({"url": url_real, "tiene_login": hay_login,
                             "tiene_busqueda": hay_busqueda,
                             "tiene_formulario": hay_formulario,
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
        "endpoints_api": sorted(endpoints_api)[:30],
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
    import os
    usuario = os.environ.get("CRAWLER_USER") or None
    contrasena = os.environ.get("CRAWLER_PASS") or None
    try:
        resultado = rastrear(objetivo, max_paginas, max_prof, usuario, contrasena)
        with open(salida, "w", encoding="utf-8") as f:
            json.dump(resultado, f, ensure_ascii=False)
    except Exception as e:
        # escribir el error para que el proceso padre sepa que fallo
        with open(salida, "w", encoding="utf-8") as f:
            json.dump({"error": str(e)}, f, ensure_ascii=False)
        sys.exit(1)


if __name__ == "__main__":
    main()