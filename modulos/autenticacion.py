"""
autenticacion.py  (modulo de deteccion - A07: Authentication Failures)
Analiza la POSTURA de seguridad de la autenticacion del objetivo, SIN realizar
fuerza bruta real. En lugar de martillar el login con miles de contraseñas
(agresivo, ineficaz y eticamente cuestionable), este modulo comprueba si
existen los CONTROLES que deberian proteger el login:

  1. Rate limiting / proteccion anti fuerza bruta:
     Envia unos POCOS intentos fallidos (por defecto 5) y observa si el
     servidor los frena (bloqueo, captcha, retraso, codigo 429). Si acepta
     todos sin control, ESO es el hallazgo: falta proteccion.

  2. Enumeracion de usuarios:
     Comprueba si el sistema revela si un usuario existe (respuestas distintas
     para 'usuario no existe' vs 'contraseña incorrecta').

  3. Transmision de credenciales:
     Verifica que el login se sirva por HTTPS y no por HTTP en claro.

  4. Gestion de la cookie de sesion:
     Revisa los flags de la cookie que se establece al interactuar con el login.

Este enfoque es responsable (pocos intentos, no bloquea cuentas) y a la vez
util: mide si las defensas correctas estan presentes.

Requiere configuracion en config.yaml (seccion 'autenticacion') porque cada
login es distinto. Sin 'url_login', el modulo se salta.

Patron de siempre:
    def ejecutar(config, logger) -> list[Hallazgo]
"""

import logging
import time
from urllib.parse import urlparse

import requests

from core.modelo_hallazgo import Hallazgo


ORIGEN = "modulo_autenticacion"

# Numero de intentos por defecto para la prueba de rate limiting (POCOS).
MAX_INTENTOS_DEFECTO = 5


def ejecutar(config: dict, logger: logging.Logger) -> list[Hallazgo]:
    """
    Punto de entrada del modulo (lo llama main.py).

    Analiza los controles de autenticacion del login configurado.
    """
    conf = config.get("autenticacion", {})
    url_login = conf.get("url_login", "").strip()

    hallazgos: list[Hallazgo] = []

    # --- Sin login configurado, no hay nada que analizar ---
    if not url_login:
        logger.warning(
            "[autenticacion] No se ha configurado 'url_login' en config.yaml "
            "(seccion 'autenticacion'). Este modulo necesita saber donde esta "
            "el formulario de login. Se omite."
        )
        return hallazgos

    campo_usuario = conf.get("campo_usuario", "username")
    campo_password = conf.get("campo_password", "password")
    usuario_prueba = conf.get("usuario_prueba", "usuario_inexistente_xyz")
    usuario_valido = conf.get("usuario_valido", "")  # opcional, para enumeracion
    max_intentos = conf.get("max_intentos", MAX_INTENTOS_DEFECTO)

    opciones = config.get("opciones", {})
    timeout = opciones.get("timeout", 10)
    verificar_ssl = opciones.get("verificar_ssl", True)
    user_agent = opciones.get("user_agent", "AuditoriaWeb/1.0")

    logger.info(f"[autenticacion] Analizando el login en {url_login}")

    # --- 1. Transmision de credenciales (HTTP vs HTTPS) ---
    if urlparse(url_login).scheme != "https":
        hallazgos.append(Hallazgo(
            titulo="Formulario de login servido sobre HTTP (sin cifrar)",
            categoria="A07",
            severidad="alta",
            descripcion=(
                "El formulario de login se sirve sobre HTTP en lugar de HTTPS. "
                "Las credenciales viajan en texto claro y pueden ser "
                "interceptadas por un atacante en la red."
            ),
            cvss=7.4,
            evidencia=f"URL del login: {url_login} (esquema http)",
            recomendacion=(
                "Servir el login (y todo el sitio) exclusivamente sobre HTTPS "
                "y forzar la redireccion de HTTP a HTTPS."
            ),
            herramienta_origen=ORIGEN,
            url_afectada=url_login,
        ))
        logger.info("[autenticacion] Login sobre HTTP (sin cifrar).")

    headers = {"User-Agent": user_agent}
    sesion = requests.Session()
    sesion.headers.update(headers)

    #2. Prueba de rate limiting (POCOS intentos fallidos)
    hallazgos.extend(
        _probar_rate_limiting(
            sesion, url_login, campo_usuario, campo_password,
            usuario_prueba, max_intentos, timeout, verificar_ssl, logger
        )
    )

    #3. Enumeracion de usuarios (si se dio un usuario valido)
    if usuario_valido:
        hallazgos.extend(
            _probar_enumeracion(
                sesion, url_login, campo_usuario, campo_password,
                usuario_valido, usuario_prueba, timeout, verificar_ssl, logger
            )
        )
    else:
        logger.info(
            "[autenticacion] No se configuro 'usuario_valido'; se omite la "
            "prueba de enumeracion de usuarios."
        )

    #4. Gestion de la cookie de sesion
    hallazgos.extend(
        _revisar_cookie_sesion(sesion, url_login, logger)
    )

    logger.info(
        f"[autenticacion] Analisis terminado. {len(hallazgos)} hallazgo(s)."
    )
    return hallazgos


def _intento_login(sesion, url, campo_u, campo_p, usuario, password,
                   timeout, verificar_ssl):
    """Hace un intento de login y devuelve la respuesta (o None si falla)."""
    datos = {campo_u: usuario, campo_p: password}
    try:
        return sesion.post(
            url, data=datos, timeout=timeout, verify=verificar_ssl,
            allow_redirects=False
        )
    except requests.exceptions.RequestException:
        return None


def _probar_rate_limiting(sesion, url, campo_u, campo_p, usuario,
                          max_intentos, timeout, verificar_ssl, logger):
    """
    Envia unos pocos intentos fallidos y observa si el servidor los frena.
    Si acepta todos sin ningun control, reporta falta de rate limiting.
    """
    hallazgos = []
    logger.info(
        f"[autenticacion] Probando rate limiting con {max_intentos} intentos "
        f"fallidos (usuario de prueba, contraseña incorrecta)..."
    )

    codigos = []
    bloqueado = False
    for i in range(max_intentos):
        resp = _intento_login(
            sesion, url, campo_u, campo_p, usuario, f"passwordfalso{i}",
            timeout, verificar_ssl
        )
        if resp is None:
            logger.debug(f"[autenticacion] Intento {i+1} fallo de conexion.")
            continue

        codigos.append(resp.status_code)

        # Señales de que el servidor esta frenando los intentos.
        if resp.status_code == 429:  # Too Many Requests
            bloqueado = True
            logger.info(
                f"[autenticacion] El servidor respondio 429 en el intento "
                f"{i+1}: hay rate limiting."
            )
            break
        texto = resp.text.lower()
        if any(s in texto for s in ["captcha", "too many", "demasiados",
                                    "bloqueado", "locked", "try again later",
                                    "intente de nuevo mas tarde"]):
            bloqueado = True
            logger.info(
                f"[autenticacion] Señal de bloqueo/captcha en el intento {i+1}."
            )
            break

        time.sleep(0.5)  # pausa breve entre intentos (ser educado)

    # Si hicimos todos los intentos sin ninguna señal de bloqueo -> hallazgo.
    if not bloqueado and len(codigos) >= max_intentos:
        hallazgos.append(Hallazgo(
            titulo="Ausencia de proteccion contra fuerza bruta (sin rate limiting)",
            categoria="A07",
            severidad="media",
            descripcion=(
                f"El login acepto {max_intentos} intentos fallidos consecutivos "
                f"sin aplicar ningun control (ni bloqueo, ni captcha, ni "
                f"limitacion de tasa). Esto facilita ataques de fuerza bruta "
                f"para adivinar contraseñas."
            ),
            cvss=5.3,
            evidencia=(
                f"{max_intentos} intentos fallidos seguidos, todos aceptados. "
                f"Codigos de respuesta: {codigos}."
            ),
            recomendacion=(
                "Implementar rate limiting, bloqueo temporal tras varios "
                "intentos fallidos, y/o captcha. Considerar autenticacion de "
                "doble factor."
            ),
            herramienta_origen=ORIGEN,
            url_afectada=url,
        ))
        logger.info("[autenticacion] Sin rate limiting detectado.")

    return hallazgos


def _probar_enumeracion(sesion, url, campo_u, campo_p, usuario_valido,
                        usuario_invalido, timeout, verificar_ssl, logger):
    """
    Compara la respuesta ante un usuario valido vs uno inexistente (ambos con
    contraseña incorrecta). Si difieren mucho, el sistema permite enumerar
    usuarios.
    """
    hallazgos = []
    logger.info("[autenticacion] Probando enumeracion de usuarios...")

    r_valido = _intento_login(
        sesion, url, campo_u, campo_p, usuario_valido, "passwordfalso",
        timeout, verificar_ssl
    )
    r_invalido = _intento_login(
        sesion, url, campo_u, campo_p, usuario_invalido, "passwordfalso",
        timeout, verificar_ssl
    )

    if r_valido is None or r_invalido is None:
        logger.debug("[autenticacion] No se pudo completar la prueba de enumeracion.")
        return hallazgos

    # Comparar codigo y longitud de respuesta. Diferencias notables sugieren
    # que el sistema trata distinto a usuarios existentes vs inexistentes.
    dif_codigo = r_valido.status_code != r_invalido.status_code
    dif_longitud = abs(len(r_valido.text) - len(r_invalido.text)) > 50

    if dif_codigo or dif_longitud:
        hallazgos.append(Hallazgo(
            titulo="Posible enumeracion de usuarios",
            categoria="A07",
            severidad="baja",
            descripcion=(
                "El login responde de forma distinta ante un usuario existente "
                "y uno inexistente (con la misma contraseña incorrecta). Esto "
                "permite a un atacante averiguar que usuarios existen, un paso "
                "previo util para ataques dirigidos."
            ),
            cvss=3.7,
            evidencia=(
                f"Usuario valido -> HTTP {r_valido.status_code} "
                f"({len(r_valido.text)} bytes); "
                f"usuario inexistente -> HTTP {r_invalido.status_code} "
                f"({len(r_invalido.text)} bytes)."
            ),
            recomendacion=(
                "Devolver siempre el mismo mensaje y comportamiento ante "
                "credenciales invalidas, sin distinguir si el usuario existe."
            ),
            herramienta_origen=ORIGEN,
            url_afectada=url,
        ))
        logger.info("[autenticacion] Posible enumeracion de usuarios detectada.")

    return hallazgos


def _revisar_cookie_sesion(sesion, url, logger):
    """Revisa los flags de las cookies de sesion establecidas durante el login."""
    hallazgos = []

    # Las cookies acumuladas en la sesion tras los intentos anteriores.
    for cookie in sesion.cookies:
        nombre = cookie.name
        # Nos centramos en cookies que parecen de sesion.
        if not any(k in nombre.lower() for k in
                   ["sess", "session", "sid", "token", "auth"]):
            continue

        problemas = []
        if not cookie.secure:
            problemas.append("sin flag Secure")
        tiene_httponly = cookie.has_nonstandard_attr("HttpOnly") or \
            cookie.has_nonstandard_attr("httponly")
        if not tiene_httponly:
            problemas.append("sin flag HttpOnly")

        if problemas:
            hallazgos.append(Hallazgo(
                titulo=f"Cookie de sesion insegura: {nombre}",
                categoria="A07",
                severidad="media",
                descripcion=(
                    f"La cookie de sesion '{nombre}' presenta problemas de "
                    f"configuracion ({', '.join(problemas)}), lo que puede "
                    f"facilitar el robo de sesion (por interceptacion o XSS)."
                ),
                cvss=5.3,
                evidencia=f"Cookie '{nombre}': {', '.join(problemas)}.",
                recomendacion=(
                    "Configurar las cookies de sesion con los flags Secure y "
                    "HttpOnly, y regenerar el identificador de sesion tras el "
                    "login."
                ),
                herramienta_origen=ORIGEN,
                url_afectada=url,
            ))
            logger.info(
                f"[autenticacion] Cookie de sesion insegura: {nombre} "
                f"({', '.join(problemas)})."
            )

    return hallazgos


# Prueba independiente:
#     python3 -m modulos.autenticacion
# Requiere un objetivo con login AUTORIZADO configurado.
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    log = logging.getLogger("prueba")

    config_prueba = {
        "opciones": {"timeout": 10, "verificar_ssl": False},
        "autenticacion": {
            "url_login": "https://server.vulnapp.id/dvwa/login.php",
            "campo_usuario": "admin",
            "campo_password": "password",
            "usuario_prueba": "admin",
            "max_intentos": 50,
        },
    }

    print("Probando el modulo autenticacion ...")
    print("(Requiere un servidor con login en 127.0.0.1:8092)\n")
    resultados = ejecutar(config_prueba, log)

    print(f"\nSe generaron {len(resultados)} hallazgos:\n")
    for h in resultados:
        print(h)
        print(f"    Evidencia: {h.evidencia}")
        print()