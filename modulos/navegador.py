# modo navegador autonomo y generico (capa 2) con playwright
# proporciona herramientas visuales al agente para explorar, restringido al dominio

import os
import re
import time
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright

ERRORES_SQL = ["sql syntax", "sqlite", "psql", "ora-", "mysql_fetch",
               "you have an error in your sql", "unclosed quotation",
               "warning: mysql", "syntax error"]


def _reflejo_xss_peligroso(payload: str, contenido_html: str) -> bool:
    # verifica si el payload se refleja con html/js no escapado (posible xss)
    # evita marcar como xss reflejos textuales inofensivos. no afecta confirmacion por dialog.
    p = (payload or "").lower()
    if not p:
        return False
    tiene_html = (("<" in p and ">" in p)
                  or "javascript:" in p
                  or bool(re.search(r"on\w+\s*=", p)))
    if not tiene_html:
        return False
    return p in (contenido_html or "")


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
            self._browser = self._pw.chromium.launch(
                headless=headless,
                args=["--window-size=1280,1080", "--window-position=0,0"]
            )
        except Exception as e:
            # si falla interfaz visual (sin wslg/display), cae a modo headless y continua
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
            #record_video_size={"width": 1280, "height": 800},
            viewport={"width": 1280, "height": 800},
            ignore_https_errors=True,
        )
        self._page = self._context.new_page()
        self._page.set_default_timeout(8000)

    # utilidades

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

    # herramientas de alto nivel (las llama el agente)

    def login_real(self, url_login, usuario, contrasena):
        # inicia sesion real con credenciales (no payloads) antes de auditar
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
            self._page.wait_for_timeout(1500)  # deja que la spa termine de pintar
            self._descartar_overlays()
            self._captura(f"navegar {url}")
            return {"ok": True, "url_actual": self._page.url,
                    "titulo": self._page.title()}
        except Exception as e:
            return {"error": f"No se pudo navegar: {e}"}

    def analizar_pagina(self):
        # devuelve resumen compacto del DOM (formularios, enlaces) para decidir ataques
        try:
            self._descartar_overlays()
            self._page.wait_for_timeout(800)  # asegura dom pintado en spas
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

    def _estado_sesion(self, url_antes):
        # heuristica de sesion para spas: usa señales combinadas (storage, logout, dom)
        try:
            info = self._page.evaluate(
                """
                () => {
                  const dump = (s) => { const o={}; try { for (let i=0;i<s.length;i++){ const k=s.key(i); o[k]=s.getItem(k);} } catch(e){} return o; };
                  const all = {...dump(localStorage), ...dump(sessionStorage)};
                  const jwt = /^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$/;
                  let tokenLike = false;
                  for (const k in all) {
                    const v = (all[k]||'') + '';
                    const kn = k.toLowerCase();
                    if ((kn.includes('token')||kn.includes('jwt')||kn.includes('auth')||kn.includes('session')||kn.includes('user')) && v.length>20) tokenLike = true;
                    if (jwt.test(v)) tokenLike = true;
                  }
                  const hayPassword = !!document.querySelector('input[type=password]');
                  const txt = (document.body ? document.body.innerText : '').toLowerCase();
                  const hayLogout = /cerrar sesi|cerrar sesión|logout|log out|sign out|salir/.test(txt);
                  const hayErrorLogin = /credenciales inv|usuario o contrase|contraseña incorrect|incorrect password|invalid credential|login fail|no autorizado|unauthorized/.test(txt);
                  return {tokenLike, hayPassword, hayLogout, hayErrorLogin, claves: Object.keys(all)};
                }
                """
            )
        except Exception:
            info = {}
        url_actual = self._page.url
        url_cambio = url_actual != url_antes
        token_like = bool(info.get("tokenLike"))
        hay_password = bool(info.get("hayPassword"))
        hay_logout = bool(info.get("hayLogout"))
        hay_error = bool(info.get("hayErrorLogin"))
        # autenticado si hay senal positiva y no hay mensaje de error de login
        autenticado = (not hay_error) and (
            token_like or hay_logout or (not hay_password)
            or (url_cambio and "login" not in url_actual.lower()))
        return {"autenticado": autenticado, "url_actual": url_actual,
                "token_like": token_like, "hay_password": hay_password,
                "hay_logout": hay_logout, "hay_error_login": hay_error,
                "url_cambio": url_cambio, "claves_storage": info.get("claves", [])}

    def iniciar_sesion(self, url_login, usuario, contrasena):
        # inicia sesion real con credenciales validas
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
            return {"ok": False, "autenticado": False,
                    "error": "No se encontro el formulario de login."}
        try:
            url_antes = self._page.url
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
            try:
                self._page.wait_for_load_state("networkidle", timeout=4000)
            except Exception:
                pass
            self._captura("login real: resultado")
            estado = self._estado_sesion(url_antes)
            self._log(f"login real -> autenticado={estado['autenticado']} "
                      f"(token={estado['token_like']}, sin_password="
                      f"{not estado['hay_password']}, logout={estado['hay_logout']}, "
                      f"error={estado['hay_error_login']}, url_cambio={estado['url_cambio']})")
            return {"ok": estado["autenticado"], **estado}
        except Exception as e:
            return {"ok": False, "autenticado": False,
                    "error": f"Error en el login: {e}"}

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
            try:
                self._page.wait_for_load_state("networkidle", timeout=3000)
            except Exception:
                pass
            self._captura("login: resultado")
            url_actual = self._page.url
            tiene_token = self._page.evaluate(
                "() => !!(localStorage.getItem('token') || sessionStorage.getItem('token'))")
            exito = (url_actual != url_login) or bool(tiene_token)
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
        # inyecta payload en buscador, verifica reflejo/error e intercepta dialogs (xss confirmado)
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
            # escuchar dialogs (alert/confirm/prompt) para confirmar XSS real
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
            posible_reflejo = _reflejo_xss_peligroso(payload, contenido)
            xss_confirmado = dialog_disparado[0]
            error_sql = next((e for e in ERRORES_SQL if e in contenido), None)

            # quitar listener para no acumular
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
        # prueba IDOR: varia el id numerico de la URL original y compara respuesta
        if not self._permitida(url):
            return {"error": "URL fuera del dominio autorizado."}
        # si la URL trae caracteres de inyeccion en vez de un id limpio, se rechaza
        marcadores_inyeccion = ("'", '"', " ", "--", "%27", "%22", "%20")
        if any(m in url for m in marcadores_inyeccion):
            return {"error": "La URL no es un id limpio (parece traer un payload de "
                             "inyeccion). Para IDOR da una URL con id numerico simple, "
                             "por ejemplo .../item/5 o ...?id=5."}
        from urllib.parse import urlparse, urlunparse
        p = urlparse(url)
        # buscar el numero solo en la ruta o el query, nunca en el host:puerto
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
            contenido_orig = self._page.content() or ""
            len_orig = len(contenido_orig)

            if not self._permitida(url_var):
                return {"error": "La variacion sale del dominio autorizado."}
            self._page.goto(url_var, wait_until="domcontentloaded"); time.sleep(1.0)
            self._captura(f"idor: variacion id={id_var}")
            contenido_var = self._page.content() or ""
            len_var = len(contenido_var)

            # en un spa, se considera idor solo si la variacion devuelve contenido distinto al original
            dif = abs(len_var - len_orig)
            identicas = contenido_var == contenido_orig
            accesible = (len_var > 200 and not identicas and dif > 100)
            return {"ok": True, "id_original": id_orig, "id_variado": id_var,
                    "url_variada": url_var, "tam_original": len_orig,
                    "tam_variado": len_var, "diferencia": dif,
                    "variacion_accesible": accesible,
                    "nota": ("La variacion del id devolvio contenido DISTINTO: posible "
                             "IDOR (revisar si son datos de otro usuario)." if accesible
                             else ("La variacion devolvio la misma pagina (mismo shell): "
                                   "sin indicio de IDOR. En un SPA los datos van por API, "
                                   "revisar los endpoints."))}
        except Exception as e:
            self._captura("idor: error")
            return {"error": f"Error durante la prueba IDOR: {e}"}

    def probar_formulario(self, payload):
        # prueba inyeccion en formulario y confirma xss si se intercepta un dialog
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
            # escuchar dialogs para confirmar XSS real
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
            posible_reflejo = _reflejo_xss_peligroso(payload, contenido)
            xss_confirmado = dialog_disparado[0]
            error_sql = next((e for e in ERRORES_SQL if e in contenido), None)

            # quitar listener
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

    # ciclo de vida

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

    def finalizar_dejando_abierto(self):
        # guarda video pero deja el navegador y contexto vivos para mantener la ventana visible
        video_path = None
        cookies = []
        try:
            cookies = self._context.cookies()  # conservar sesion para la ventana visible
        except Exception:
            cookies = []
        try:
            video = self._page.video
            self._context.close()   # finaliza y guarda el video de la sesion
            if video:
                video_path = video.path()
        except Exception as e:
            self._log(f"cierre de contexto (video): {e}")
        # abre nueva pestana reinyectando cookies para mantener la vista autenticada
        try:
            self._context = self._browser.new_context(
                ignore_https_errors=True,
                viewport={"width": 1280, "height": 800})
            if cookies:
                try:
                    self._context.add_cookies(cookies)
                except Exception:
                    pass
            self._page = self._context.new_page()
            try:
                self._page.goto(self.url_objetivo, wait_until="domcontentloaded",
                                timeout=12000)
            except Exception:
                pass
        except Exception as e:
            self._log(f"no se pudo dejar el navegador abierto: {e}")
        if video_path:
            self._log(f"video de la sesion -> {video_path}")
        return video_path


def declarar_tools_navegador():
    # tools genericas de alto nivel (optimizadas para llms 7b 8b)
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