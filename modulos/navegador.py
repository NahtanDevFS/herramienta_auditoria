"""
navegador.py  —  Modo navegador AUTONOMO y GENERICO para el agente (CAPA 2)

Da al agente un navegador real (Playwright) con herramientas GENERICAS que
funcionan en CUALQUIER sitio web (no asume rutas ni tecnologias concretas):

  - analizar_pagina : los "ojos". Devuelve un resumen COMPACTO de la pagina
                      (formularios, campos, buscadores, enlaces con parametros)
                      para que el modelo decida que atacar segun lo que hay.
  - navegar         : abre una URL del objetivo y captura.
  - probar_login    : rellena y envia un formulario de login (bypass SQLi).
  - probar_busqueda : inyecta un payload en un input de busqueda/texto y detecta
                      reflejo (XSS) o errores SQL.
  - probar_idor     : navega variaciones del id de una URL (control de acceso).
  - tomar_captura   : captura del estado actual.

Cada accion toma una captura, y toda la sesion se graba en video.
Guardarrailes: todo se restringe al dominio del objetivo.

Requiere:
    pip install playwright
    playwright install chromium
    playwright install-deps        # (WSL/Ubuntu; con sudo)
"""

import os
import re
import time
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright

ERRORES_SQL = ["sql syntax", "sqlite", "psql", "ora-", "mysql_fetch",
               "you have an error in your sql", "unclosed quotation",
               "warning: mysql", "syntax error"]


class NavegadorAgente:

    def __init__(self, url_objetivo, carpeta_capturas="resultados/capturas",
                 carpeta_video="resultados/video", headless=True,
                 logger=None, callback_captura=None):
        self.url_objetivo = url_objetivo
        self.dominio = urlparse(url_objetivo).netloc
        self.logger = logger
        self.callback_captura = callback_captura
        self.capturas = []
        self._n = 0

        os.makedirs(carpeta_capturas, exist_ok=True)
        os.makedirs(carpeta_video, exist_ok=True)
        self.carpeta_capturas = carpeta_capturas

        self._pw = sync_playwright().start()
        try:
            self._browser = self._pw.chromium.launch(headless=headless)
        except Exception as e:
            # headless=False falla si no hay pantalla (sin WSLg / sin DISPLAY).
            # En vez de romper, caemos a modo oculto y seguimos (las capturas y
            # el panel en vivo siguen funcionando igual).
            if not headless:
                if logger:
                    logger.warning(f"[navegador] No se pudo abrir ventana visible "
                                   f"({e}); usando modo oculto. Para ver la ventana en "
                                   f"WSL necesitas WSLg (Windows 11) y $DISPLAY.")
                self._browser = self._pw.chromium.launch(headless=True)
            else:
                raise
        self._context = self._browser.new_context(
            record_video_dir=carpeta_video,
            viewport={"width": 1280, "height": 800},
            ignore_https_errors=True,
        )
        self._page = self._context.new_page()
        self._page.set_default_timeout(8000)

    # ----- utilidades ---------------------------------------------------------

    def _log(self, msg):
        if self.logger:
            self.logger.info(f"[navegador] {msg}")

    def _permitida(self, url):
        try:
            netloc = urlparse(url).netloc
            return netloc == "" or netloc == self.dominio
        except Exception:
            return False

    def _captura(self, etiqueta):
        self._n += 1
        ruta = os.path.join(self.carpeta_capturas, f"paso_{self._n:02d}.png")
        try:
            self._page.screenshot(path=ruta, full_page=False)
            self.capturas.append(ruta)
            self._log(f"captura -> {ruta} ({etiqueta})")
            if self.callback_captura:
                self.callback_captura(ruta, etiqueta)
        except Exception as e:
            self._log(f"no se pudo capturar: {e}")
        return ruta

    def _encontrar(self, selectores):
        for sel in selectores:
            try:
                loc = self._page.locator(sel).first
                if loc.count() > 0 and loc.is_visible():
                    return loc
            except Exception:
                continue
        return None

    def _descartar_overlays(self):
        botones = [
            "button[aria-label='Close Welcome Banner']",
            "a[aria-label='dismiss cookie message']",
            "button:has-text('Dismiss')", "button:has-text('Me too')",
            "button:has-text('Aceptar')", "button:has-text('Accept')",
            "button:has-text('Got it')", "button:has-text('OK')",
            "button:has-text('Entendido')",
        ]
        for sel in botones:
            try:
                loc = self._page.locator(sel).first
                if loc.count() > 0 and loc.is_visible():
                    loc.click(timeout=1500)
                    self._log(f"overlay cerrado: {sel}")
                    time.sleep(0.2)
            except Exception:
                continue

    # ----- herramientas de alto nivel (las llama el agente) -------------------

    def login_real(self, url_login, usuario, contrasena):
        """
        Inicia sesion con credenciales REALES (no payloads). Se usa como paso
        previo para auditar la zona autenticada. Devuelve si logro entrar.
        NOTA: las credenciales no se registran en logs ni en capturas de texto.
        """
        try:
            self.navegar(url_login)
        except Exception:
            pass
        self._descartar_overlays()
        campo_user = self._encontrar([
            "input[type=email]", "input[name*=email i]", "input[id*=email i]",
            "input[name*=user i]", "input[id*=user i]", "input[type=text]",
        ])
        campo_pass = self._encontrar([
            "input[type=password]", "input[name*=pass i]", "input[id*=pass i]",
        ])
        if not campo_user or not campo_pass:
            return {"ok": False, "error": "No se encontro el formulario de login."}
        try:
            campo_user.fill(usuario)
            campo_pass.fill(contrasena)
            self._captura("login real: credenciales ingresadas")
            boton = self._encontrar([
                "button[type=submit]", "#loginButton", "input[type=submit]",
                "button:has-text('Log in')", "button:has-text('Login')",
                "button:has-text('Iniciar')", "button:has-text('Entrar')",
            ])
            if boton:
                try:
                    boton.click()
                except Exception:
                    boton.click(force=True)
            else:
                campo_pass.press("Enter")
            time.sleep(1.8)
            self._captura("login real: resultado")
            tiene_token = self._page.evaluate(
                "() => !!(localStorage.getItem('token') || sessionStorage.getItem('token'))")
            autenticado = bool(tiene_token) or ("login" not in self._page.url.lower())
            return {"ok": autenticado, "url_actual": self._page.url,
                    "token_presente": bool(tiene_token)}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def navegar(self, url):
        if not self._permitida(url):
            return {"error": "URL fuera del dominio autorizado. Navegacion rechazada."}
        try:
            try:
                self._page.goto(url, wait_until="networkidle", timeout=12000)
            except Exception:
                self._page.goto(url, wait_until="domcontentloaded")
            self._page.wait_for_timeout(1500)  # deja que la SPA termine de pintar
            self._descartar_overlays()
            self._captura(f"navegar {url}")
            return {"ok": True, "url_actual": self._page.url,
                    "titulo": self._page.title()}
        except Exception as e:
            return {"error": f"No se pudo navegar: {e}"}

    def analizar_pagina(self):
        """
        LOS OJOS. Devuelve un resumen compacto de la superficie de ataque de la
        pagina actual, para que el modelo decida que probar (sin conocimiento
        previo del sitio). Compacto a proposito: un 7B digiere mejor algo corto.
        """
        try:
            self._descartar_overlays()
            self._page.wait_for_timeout(800)  # asegura DOM pintado en SPAs
            datos = self._page.evaluate(
                """
                () => {
                  const forms = [...document.querySelectorAll('form')].slice(0,8).map((f,i) => {
                    const campos = [...f.querySelectorAll('input,textarea,select')]
                      .map(el => ({nombre: el.name||el.id||el.getAttribute('placeholder')||'',
                                   tipo: (el.type||el.tagName||'').toLowerCase()}))
                      .filter(c => c.tipo!=='hidden' && c.tipo!=='submit' && c.tipo!=='button');
                    return {indice:i, accion:f.getAttribute('action')||'',
                            tiene_password: campos.some(c => c.tipo==='password'),
                            campos: campos.slice(0,8)};
                  });
                  const buscadores = [...document.querySelectorAll('input')].filter(el => {
                    const t=(el.type||'').toLowerCase();
                    const n=((el.name||'')+(el.id||'')+(el.getAttribute('placeholder')||'')).toLowerCase();
                    return t==='search' || /search|buscar|query|\\bq\\b/.test(n);
                  }).slice(0,5).map(el => ({nombre: el.name||el.id||el.getAttribute('placeholder')||'',
                                            tipo:(el.type||'text')}));
                  const enlaces = [...new Set([...document.querySelectorAll('a[href]')]
                    .map(a=>a.href).filter(h => h.includes('?') && h.includes('=')))].slice(0,15);
                  // rutas internas descubiertas (incluye rutas hash de SPAs y routerlink Angular)
                  const rutas = [...new Set([...document.querySelectorAll('a[href],[routerlink]')]
                    .map(a => a.getAttribute('routerlink') || a.getAttribute('href') || '')
                    .filter(h => h && (h.startsWith('/') || h.startsWith('#') ||
                                       h.includes(location.host))))].slice(0,20);
                  return {forms, buscadores, enlaces, rutas};
                }
                """
            )
            self._captura("analizar pagina")
            forms = datos.get("forms", [])
            buscadores = datos.get("buscadores", [])
            enlaces = datos.get("enlaces", [])
            rutas = datos.get("rutas", [])
            hay_login = any(f.get("tiene_password") for f in forms)
            resumen = (
                f"{len(forms)} formulario(s)"
                + (" (uno con login)" if hay_login else "")
                + f"; {len(buscadores)} campo(s) de busqueda"
                + f"; {len(enlaces)} enlace(s) con parametros"
                + f"; {len(rutas)} ruta(s) internas descubiertas."
            )
            return {
                "ok": True,
                "url_actual": self._page.url,
                "resumen": resumen,
                "hay_login": hay_login,
                "formularios": forms,
                "buscadores": buscadores,
                "enlaces_con_parametros": enlaces,
                "rutas_descubiertas": rutas,
            }
        except Exception as e:
            return {"error": f"No se pudo analizar la pagina: {e}"}

    def iniciar_sesion(self, url_login, usuario, contrasena):
        """
        Inicia sesion REAL con credenciales validas (no payloads). Se usa como paso
        previo para auditar la zona autenticada. Devuelve si el login tuvo exito.
        """
        try:
            self.navegar(url_login)
        except Exception:
            pass
        self._descartar_overlays()
        campo_user = self._encontrar([
            "input[type=email]", "input[name*=email i]", "input[id*=email i]",
            "input[name*=user i]", "input[id*=user i]", "input[type=text]",
        ])
        campo_pass = self._encontrar([
            "input[type=password]", "input[name*=pass i]", "input[id*=pass i]",
        ])
        if not campo_user or not campo_pass:
            return {"ok": False, "error": "No se encontro el formulario de login."}
        try:
            campo_user.fill(usuario)
            campo_pass.fill(contrasena)
            self._captura("login real: credenciales ingresadas")
            boton = self._encontrar([
                "button[type=submit]", "#loginButton", "input[type=submit]",
                "button:has-text('Log in')", "button:has-text('Login')",
                "button:has-text('Iniciar')", "button:has-text('Entrar')",
            ])
            if boton:
                try:
                    boton.click()
                except Exception:
                    campo_pass.press("Enter")
            else:
                campo_pass.press("Enter")
            time.sleep(1.8)
            self._captura("login real: resultado")
            tiene_token = self._page.evaluate(
                "() => !!(localStorage.getItem('token') || sessionStorage.getItem('token'))")
            return {"ok": bool(tiene_token), "autenticado": bool(tiene_token),
                    "url_actual": self._page.url}
        except Exception as e:
            return {"ok": False, "error": f"Error en el login: {e}"}

    def probar_login(self, usuario, contrasena):
        self._descartar_overlays()
        url_login = self._page.url   # URL donde se prueba (antes del redirect)
        campo_user = self._encontrar([
            "input[type=email]", "input[name*=email i]", "input[id*=email i]",
            "input[name*=user i]", "input[id*=user i]", "input[type=text]",
        ])
        campo_pass = self._encontrar([
            "input[type=password]", "input[name*=pass i]", "input[id*=pass i]",
        ])
        if not campo_user or not campo_pass:
            self._captura("login: campos no encontrados")
            return {"error": "No se encontraron campos de usuario/contrasena. "
                             "Navega a una pagina de login o usa analizar_pagina."}
        try:
            campo_user.fill(usuario)
            campo_pass.fill(contrasena)
            self._captura(f"login: datos ingresados (user={usuario!r})")
            boton = self._encontrar([
                "button[type=submit]", "input[type=submit]",
                "button:has-text('Log in')", "button:has-text('Login')",
                "button:has-text('Iniciar')", "button:has-text('Entrar')",
                "#loginButton",
            ])
            enviado = False
            if boton:
                try:
                    boton.click(); enviado = True
                except Exception:
                    self._descartar_overlays()
                    try:
                        boton.click(force=True); enviado = True
                    except Exception:
                        pass
            if not enviado:
                campo_pass.press("Enter")
            time.sleep(1.6)
            self._captura("login: resultado")
            url_actual = self._page.url
            tiene_token = self._page.evaluate(
                "() => !!(localStorage.getItem('token') || sessionStorage.getItem('token'))")
            exito = ("login" not in url_actual.lower()) or bool(tiene_token)
            return {"ok": True, "url_actual": url_actual, "url_login": url_login,
                    "posible_exito": exito,
                    "token_presente": bool(tiene_token),
                    "nota": ("Login exitoso: posible bypass de autenticacion por SQLi."
                             if exito else
                             "Este payload no paso; probar otra variante.")}
        except Exception as e:
            self._captura("login: error")
            return {"error": f"Error durante el login: {e}"}

    def probar_busqueda(self, payload):
        """
        Inyecta un payload en un campo de busqueda/texto y detecta si se refleja
        (posible XSS) o si aparecen errores SQL (posible inyeccion SQL).
        Si el payload contiene un script con alert(), escucha el evento 'dialog'
        para confirmar ejecucion real (no solo reflejo textual).
        """
        self._descartar_overlays()
        campo = self._encontrar([
            "input[type=search]", "input[name*=search i]", "input[id*=search i]",
            "input[placeholder*=search i]", "input[placeholder*=buscar i]",
            "input[name=q]", "input[type=text]",
        ])
        if not campo:
            self._captura("busqueda: sin campo")
            return {"error": "No se encontro un campo de busqueda/texto. "
                             "Usa analizar_pagina para ver que inputs hay."}
        try:
            # Escuchar dialogs (alert/confirm/prompt) para confirmar XSS real.
            dialog_disparado = [False]
            def _on_dialog(dialog):
                dialog_disparado[0] = True
                try:
                    dialog.dismiss()
                except Exception:
                    pass
            self._page.on("dialog", _on_dialog)

            campo.fill(payload)
            self._captura(f"busqueda: payload ingresado ({payload!r})")
            campo.press("Enter")
            time.sleep(1.5)
            self._captura("busqueda: resultado")
            contenido = (self._page.content() or "").lower()
            posible_reflejo = payload.lower() in contenido
            xss_confirmado = dialog_disparado[0]
            error_sql = next((e for e in ERRORES_SQL if e in contenido), None)

            # Quitar listener para no acumular.
            try:
                self._page.remove_listener("dialog", _on_dialog)
            except Exception:
                pass

            return {"ok": True, "url_actual": self._page.url,
                    "posible_reflejo_xss": posible_reflejo,
                    "xss_confirmado": xss_confirmado,
                    "posible_error_sql": bool(error_sql),
                    "detalle_sql": error_sql or "",
                    "nota": ("XSS CONFIRMADO: el script se ejecuto (dialog detectado)."
                             if xss_confirmado else
                             ("El payload se refleja en la respuesta: posible XSS "
                              "(no se confirmo ejecucion)."
                              if posible_reflejo else
                              ("Se detecto un error SQL: posible inyeccion." if error_sql
                               else "Sin senales claras con este payload.")))}
        except Exception as e:
            self._captura("busqueda: error")
            return {"error": f"Error durante la busqueda: {e}"}

    def probar_idor(self, url):
        """
        Prueba control de acceso (IDOR): navega a una URL con id numerico y a una
        variacion del id, y compara. El modelo interpreta si accedio a algo ajeno.
        """
        if not self._permitida(url):
            return {"error": "URL fuera del dominio autorizado."}
        from urllib.parse import urlparse, urlunparse
        p = urlparse(url)
        # Buscar el numero SOLO en la ruta o el query, nunca en el host:puerto.
        if re.search(r"\d", p.query or ""):
            zona, es_query = p.query, True
        elif re.search(r"\d", p.path or ""):
            zona, es_query = p.path, False
        else:
            return {"error": "La URL no tiene un id numerico en la ruta o el query "
                             "que variar. Da una URL tipo .../item/5 o ...?id=5."}
        m = re.search(r"(\d+)(?!.*\d)", zona)  # ultimo numero de esa zona
        try:
            id_orig = int(m.group(1))
            id_var = id_orig + 1
            nueva = zona[:m.start()] + str(id_var) + zona[m.end():]
            if es_query:
                url_var = urlunparse((p.scheme, p.netloc, p.path, p.params, nueva, p.fragment))
            else:
                url_var = urlunparse((p.scheme, p.netloc, nueva, p.params, p.query, p.fragment))

            self._page.goto(url, wait_until="domcontentloaded"); time.sleep(1.0)
            self._captura(f"idor: original id={id_orig}")
            len_orig = len(self._page.content() or "")

            if not self._permitida(url_var):
                return {"error": "La variacion sale del dominio autorizado."}
            self._page.goto(url_var, wait_until="domcontentloaded"); time.sleep(1.0)
            self._captura(f"idor: variacion id={id_var}")
            len_var = len(self._page.content() or "")

            accesible = len_var > 200
            return {"ok": True, "id_original": id_orig, "id_variado": id_var,
                    "url_variada": url_var, "tam_original": len_orig,
                    "tam_variado": len_var, "variacion_accesible": accesible,
                    "nota": ("La variacion del id devolvio contenido: posible IDOR "
                             "(revisar si son datos de otro usuario)." if accesible
                             else "La variacion no devolvio contenido util.")}
        except Exception as e:
            self._captura("idor: error")
            return {"error": f"Error durante la prueba IDOR: {e}"}

    def probar_formulario(self, payload):
        """
        Prueba inyeccion en un formulario GENERICO (contacto, feedback, perfil):
        rellena el primer campo de texto/area no-password con el payload, lo envia,
        y detecta reflejo (XSS) o errores SQL. Distinto de probar_busqueda (que
        busca inputs de busqueda): esto ataca formularios de datos.
        Si el payload contiene un script con alert(), escucha el evento 'dialog'
        para confirmar ejecucion real.
        """
        self._descartar_overlays()
        campo = self._encontrar([
            "form textarea", "form input[type=text]", "form input[type=email]",
            "form input[type=search]", "form input:not([type])",
            "textarea", "input[type=text]", "input[type=email]",
        ])
        if not campo:
            self._captura("formulario: sin campo de texto")
            return {"error": "No se encontro un campo de texto en un formulario. "
                             "Usa analizar_pagina para ver los formularios disponibles."}
        try:
            # Escuchar dialogs para confirmar XSS real.
            dialog_disparado = [False]
            def _on_dialog(dialog):
                dialog_disparado[0] = True
                try:
                    dialog.dismiss()
                except Exception:
                    pass
            self._page.on("dialog", _on_dialog)

            campo.fill(payload)
            self._captura(f"formulario: payload ingresado ({payload!r})")
            boton = self._encontrar([
                "form button[type=submit]", "form input[type=submit]",
                "button[type=submit]", "button:has-text('Submit')",
                "button:has-text('Enviar')", "button:has-text('Send')",
            ])
            if boton:
                try:
                    boton.click()
                except Exception:
                    self._descartar_overlays()
                    try:
                        boton.click(force=True)
                    except Exception:
                        campo.press("Enter")
            else:
                campo.press("Enter")
            time.sleep(1.5)
            self._captura("formulario: resultado")
            contenido = (self._page.content() or "").lower()
            posible_reflejo = payload.lower() in contenido
            xss_confirmado = dialog_disparado[0]
            error_sql = next((e for e in ERRORES_SQL if e in contenido), None)

            # Quitar listener.
            try:
                self._page.remove_listener("dialog", _on_dialog)
            except Exception:
                pass

            return {"ok": True, "url_actual": self._page.url,
                    "posible_reflejo_xss": posible_reflejo,
                    "xss_confirmado": xss_confirmado,
                    "posible_error_sql": bool(error_sql),
                    "detalle_sql": error_sql or "",
                    "nota": ("XSS CONFIRMADO: el script se ejecuto (dialog detectado)."
                             if xss_confirmado else
                             ("El payload se refleja: posible XSS (no se confirmo "
                              "ejecucion)." if posible_reflejo
                              else ("Error SQL detectado: posible inyeccion." if error_sql
                                    else "Sin senales claras con este payload.")))}
        except Exception as e:
            self._captura("formulario: error")
            return {"error": f"Error al probar el formulario: {e}"}

    def tomar_captura(self, nota=""):
        ruta = self._captura(nota or "captura manual")
        return {"ok": True, "captura": ruta}

    # ----- ciclo de vida ------------------------------------------------------

    def cerrar(self):
        video_path = None
        try:
            video = self._page.video
            self._context.close()
            if video:
                video_path = video.path()
        except Exception as e:
            self._log(f"cierre: {e}")
        finally:
            try:
                self._browser.close()
            except Exception:
                pass
            try:
                self._pw.stop()
            except Exception:
                pass
        if video_path:
            self._log(f"video de la sesion -> {video_path}")
        return video_path


def declarar_tools_navegador():
    """Tools genericas (funcionan en cualquier sitio). Alto nivel = faciles para un 7B."""
    return [
        {"type": "function", "function": {
            "name": "navegar",
            "description": "Abre una URL del objetivo en el navegador y captura. "
                           "Usar antes de analizar o interactuar.",
            "parameters": {"type": "object",
                           "properties": {"url": {"type": "string"}},
                           "required": ["url"]}}},
        {"type": "function", "function": {
            "name": "analizar_pagina",
            "description": "Devuelve un resumen compacto de la pagina actual: "
                           "formularios y sus campos, si hay login, campos de "
                           "busqueda, y enlaces con parametros. Usalo para DECIDIR "
                           "que probar segun lo que realmente hay en la pagina.",
            "parameters": {"type": "object", "properties": {}, "required": []}}},
        {"type": "function", "function": {
            "name": "probar_login",
            "description": "Rellena y envia el formulario de login de la pagina "
                           "actual. Para bypass de autenticacion prueba usuario="
                           "\"' OR 1=1--\" con cualquier contrasena.",
            "parameters": {"type": "object", "properties": {
                "usuario": {"type": "string"}, "contrasena": {"type": "string"}},
                "required": ["usuario", "contrasena"]}}},
        {"type": "function", "function": {
            "name": "probar_busqueda",
            "description": "Inyecta un payload en un campo de busqueda/texto y "
                           "detecta reflejo (XSS) o errores SQL. Prueba payloads "
                           "como \"<script>alert(1)</script>\" o \"' OR 1=1--\".",
            "parameters": {"type": "object",
                           "properties": {"payload": {"type": "string"}},
                           "required": ["payload"]}}},
        {"type": "function", "function": {
            "name": "probar_idor",
            "description": "Prueba control de acceso (IDOR) en una URL con id "
                           "numerico: navega el id original y una variacion y "
                           "compara. Da una URL como .../item/5 o ...?id=5.",
            "parameters": {"type": "object",
                           "properties": {"url": {"type": "string"}},
                           "required": ["url"]}}},
        {"type": "function", "function": {
            "name": "probar_formulario",
            "description": "Inyecta un payload en un formulario de datos (contacto, "
                           "feedback, perfil) de la pagina actual y detecta reflejo "
                           "(XSS) o errores SQL. Prueba payloads como "
                           "\"<script>alert(1)</script>\" o \"' OR 1=1--\".",
            "parameters": {"type": "object",
                           "properties": {"payload": {"type": "string"}},
                           "required": ["payload"]}}},
        {"type": "function", "function": {
            "name": "tomar_captura",
            "description": "Toma una captura del estado actual de la pagina.",
            "parameters": {"type": "object",
                           "properties": {"nota": {"type": "string"}},
                           "required": []}}},
    ]