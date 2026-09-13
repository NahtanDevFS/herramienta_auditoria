"""
navegador.py  —  Modo navegador para el agente de pentesting (CAPA 1)

Da al agente un navegador REAL (Playwright) para interactuar visualmente con el
sitio: navegar, probar logins, y capturar lo que ocurre. A diferencia de las
tools HTTP (que usan 'requests' y no se ven), esto permite VER las acciones:
se toma una captura tras cada paso y se graba un video de toda la sesion.

Diseno pensado para un LLM local pequeno (7B): las herramientas son de ALTO
NIVEL (el modelo aporta datos/payloads; este codigo maneja el DOM). Asi el
tool-calling sigue siendo simple y fiable.

Guardarrailes: toda navegacion se restringe al dominio del objetivo.

Requiere:
    pip install playwright
    playwright install chromium
    playwright install-deps        # (en WSL/Ubuntu; necesita sudo)
"""

import os
import time
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright


class NavegadorAgente:
    """Envuelve un navegador Playwright con acciones de alto nivel y capturas."""

    def __init__(self, url_objetivo, carpeta_capturas="resultados/capturas",
                 carpeta_video="resultados/video", headless=True,
                 logger=None, callback_captura=None):
        """
        callback_captura: funcion opcional que se llama con (ruta_png, etiqueta)
        tras cada captura. La usa la interfaz Streamlit para el panel en vivo
        (capa 2). En modo standalone se deja en None.
        """
        self.url_objetivo = url_objetivo
        self.dominio = urlparse(url_objetivo).netloc
        self.logger = logger
        self.callback_captura = callback_captura
        self.capturas = []          # rutas de las capturas, en orden
        self._n = 0

        os.makedirs(carpeta_capturas, exist_ok=True)
        os.makedirs(carpeta_video, exist_ok=True)
        self.carpeta_capturas = carpeta_capturas

        self._pw = sync_playwright().start()
        self._browser = self._pw.chromium.launch(headless=headless)
        self._context = self._browser.new_context(
            record_video_dir=carpeta_video,
            viewport={"width": 1280, "height": 800},
            ignore_https_errors=True,
        )
        self._page = self._context.new_page()
        self._page.set_default_timeout(8000)

    # ----- utilidades internas ------------------------------------------------

    def _log(self, msg):
        if self.logger:
            self.logger.info(f"[navegador] {msg}")

    def _permitida(self, url):
        try:
            netloc = urlparse(url).netloc
            # permitir url relativas o del mismo dominio
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
        """Devuelve el primer locator visible de una lista de selectores."""
        for sel in selectores:
            try:
                loc = self._page.locator(sel).first
                if loc.count() > 0 and loc.is_visible():
                    return loc
            except Exception:
                continue
        return None

    def _descartar_overlays(self):
        """
        Cierra banners/pop-ups que tapan la pagina e interceptan los clics
        (cookies, bienvenida, etc.). Es lo que rompia el login en Juice Shop:
        un overlay 'intercepts pointer events'. Se intenta de forma tolerante:
        si un boton no esta, se ignora y se sigue.
        """
        botones_cerrar = [
            "button[aria-label='Close Welcome Banner']",
            "button#mat-dialog-0 button",
            "button:has-text('Dismiss')",
            "button:has-text('Me too')",       # banner de cookies de Juice Shop
            "a[aria-label='dismiss cookie message']",
            "button:has-text('Aceptar')",
            "button:has-text('Accept')",
            "button:has-text('Got it')",
            "button:has-text('OK')",
        ]
        for sel in botones_cerrar:
            try:
                loc = self._page.locator(sel).first
                if loc.count() > 0 and loc.is_visible():
                    loc.click(timeout=1500)
                    self._log(f"overlay cerrado: {sel}")
                    time.sleep(0.3)
            except Exception:
                continue

    # ----- herramientas de alto nivel (las llama el agente) -------------------

    def navegar(self, url):
        if not self._permitida(url):
            return {"error": "URL fuera del dominio autorizado. Navegacion rechazada."}
        try:
            self._page.goto(url, wait_until="domcontentloaded")
            time.sleep(1.2)  # deja que la SPA pinte
            self._descartar_overlays()  # cierra banners que tapan la pagina
            self._captura(f"navegar {url}")
            return {"ok": True, "url_actual": self._page.url,
                    "titulo": self._page.title()}
        except Exception as e:
            return {"error": f"No se pudo navegar: {e}"}

    def probar_login(self, usuario, contrasena):
        """
        Rellena y envia un formulario de login. Encuentra los campos de forma
        robusta (varios selectores comunes + fallback). Ideal para probar
        inyeccion SQL en autenticacion (usuario = "' OR 1=1--", etc.).
        """
        # Por si un overlay aparecio despues de navegar, lo cerramos de nuevo.
        self._descartar_overlays()

        campo_user = self._encontrar([
            "input[type=email]", "input[name*=email i]", "input[id*=email i]",
            "input[name*=user i]", "input[id*=user i]", "#email",
            "input[type=text]",
        ])
        campo_pass = self._encontrar([
            "input[type=password]", "input[name*=pass i]", "input[id*=pass i]",
            "#password",
        ])
        if not campo_user or not campo_pass:
            self._captura("login: campos no encontrados")
            return {"error": "No se encontraron los campos de usuario/contrasena "
                             "en la pagina actual. Navega primero al login."}
        try:
            campo_user.fill(usuario)
            campo_pass.fill(contrasena)
            self._captura(f"login: datos ingresados (user={usuario!r})")

            boton = self._encontrar([
                "#loginButton", "button[type=submit]",
                "button:has-text('Log in')", "button:has-text('Login')",
                "button:has-text('Iniciar')", "input[type=submit]",
            ])
            enviado = False
            if boton:
                try:
                    boton.click()
                    enviado = True
                except Exception:
                    # Si un overlay intercepta, reintentar tras cerrarlo, y si
                    # aun asi falla, forzar el clic o enviar con Enter.
                    self._descartar_overlays()
                    try:
                        boton.click(force=True)
                        enviado = True
                    except Exception:
                        pass
            if not enviado:
                campo_pass.press("Enter")

            time.sleep(1.8)
            self._captura("login: resultado")

            # Heuristica simple de exito: cambio de URL fuera de /login o
            # aparicion de un token de sesion.
            url_actual = self._page.url
            tiene_token = self._page.evaluate(
                "() => !!(localStorage.getItem('token') || "
                "sessionStorage.getItem('token'))"
            )
            exito = ("login" not in url_actual.lower()) or bool(tiene_token)

            return {
                "ok": True,
                "url_actual": url_actual,
                "posible_exito": exito,
                "token_presente": bool(tiene_token),
                "nota": ("El login parece haber tenido exito: posible bypass de "
                         "autenticacion por inyeccion SQL." if exito else
                         "El login no parece haber pasado con este payload; "
                         "probar otra variante (p.ej. \"' OR 1=1--\")."),
            }
        except Exception as e:
            self._captura("login: error")
            return {"error": f"Error durante el login: {e}"}

    def tomar_captura(self, nota=""):
        ruta = self._captura(nota or "captura manual")
        return {"ok": True, "captura": ruta}

    # ----- ciclo de vida ------------------------------------------------------

    def cerrar(self):
        """Cierra el navegador y finaliza el video. Devuelve la ruta del video."""
        video_path = None
        try:
            video = self._page.video
            self._context.close()          # finaliza la grabacion
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


# Declaraciones de tools (estilo OpenAI/Ollama) para el modo navegador.
# El agente las usa igual que las HTTP. Alto nivel = faciles para un 7B.
def declarar_tools_navegador():
    return [
        {
            "type": "function",
            "function": {
                "name": "navegar",
                "description": "Abre una URL del objetivo en el navegador y toma "
                               "una captura. Usar antes de interactuar con la pagina.",
                "parameters": {
                    "type": "object",
                    "properties": {"url": {"type": "string"}},
                    "required": ["url"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "probar_login",
                "description": "Rellena el formulario de login de la pagina actual "
                               "con un usuario y contrasena y lo envia. Sirve para "
                               "probar inyeccion SQL en autenticacion. Para saltarse "
                               "el login prueba usuario=\"' OR 1=1--\" (con doble guion "
                               "al final) y cualquier contrasena.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "usuario": {"type": "string"},
                        "contrasena": {"type": "string"},
                    },
                    "required": ["usuario", "contrasena"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "tomar_captura",
                "description": "Toma una captura del estado actual de la pagina.",
                "parameters": {
                    "type": "object",
                    "properties": {"nota": {"type": "string"}},
                    "required": [],
                },
            },
        },
    ]