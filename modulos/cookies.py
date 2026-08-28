"""
cookies.py  (modulo de deteccion - A04: Cryptographic Failures)
Revisa las cookies que envia la web y comprueba que tengan los flags de
seguridad recomendados. Por cada cookie con un flag ausente o mal puesto,
genera un Hallazgo.

Flags que revisamos y por que importan:
  - Secure   : la cookie solo se envia por HTTPS. Sin el, puede viajar en
               claro por HTTP y ser interceptada.
  - HttpOnly : el JavaScript de la pagina no puede leer la cookie. Sin el,
               un XSS podria robar la cookie de sesion.
  - SameSite : controla si la cookie se envia en peticiones de otros sitios.
               Sin un valor adecuado (Lax o Strict), facilita ataques CSRF.

Sigue el mismo patron que cabeceras_http:
    def ejecutar(config, logger) -> list[Hallazgo]
El modulo solo detecta y devuelve; el orquestador (main.py) recoge la lista.
"""

import logging

import requests

from core.modelo_hallazgo import Hallazgo


ORIGEN = "modulo_cookies"


def _analizar_cookie(cookie, objetivo: str) -> list[Hallazgo]:
    """
    Analiza UNA cookie y devuelve los hallazgos de los flags que le falten.

    'cookie' es un objeto del cookiejar de requests, del que podemos leer:
      - cookie.secure        -> True/False (flag Secure)
      - cookie.has_nonstandard_attr('HttpOnly') -> flag HttpOnly
      - cookie._rest          -> dict con atributos extra como SameSite
    """
    hallazgos: list[Hallazgo] = []
    nombre = cookie.name

    #Flag Secure
    if not cookie.secure:
        hallazgos.append(Hallazgo(
            titulo=f"Cookie sin flag Secure: {nombre}",
            categoria="A04",
            severidad="media",
            descripcion=(
                f"La cookie '{nombre}' no tiene el flag Secure, por lo que "
                f"puede transmitirse por conexiones HTTP en texto claro y ser "
                f"interceptada por un atacante en la red."
            ),
            cvss=5.3,
            evidencia=f"Set-Cookie: {nombre} (sin atributo 'Secure')",
            recomendacion=(
                "Añadir el atributo Secure a la cookie para que solo se envie "
                "por HTTPS."
            ),
            herramienta_origen=ORIGEN,
            url_afectada=objetivo,
        ))

    #Flag HttpOnly
    # requests guarda los atributos no estandar en cookie._rest (claves
    # insensibles a mayusculas). HttpOnly aparece ahi si esta presente.
    tiene_httponly = cookie.has_nonstandard_attr("HttpOnly") or \
        cookie.has_nonstandard_attr("httponly")
    if not tiene_httponly:
        hallazgos.append(Hallazgo(
            titulo=f"Cookie sin flag HttpOnly: {nombre}",
            categoria="A04",
            severidad="media",
            descripcion=(
                f"La cookie '{nombre}' no tiene el flag HttpOnly, por lo que "
                f"es accesible desde JavaScript. Si el sitio tiene una "
                f"vulnerabilidad XSS, un atacante podria robar esta cookie."
            ),
            cvss=5.3,
            evidencia=f"Set-Cookie: {nombre} (sin atributo 'HttpOnly')",
            recomendacion=(
                "Añadir el atributo HttpOnly, especialmente a las cookies de "
                "sesion."
            ),
            herramienta_origen=ORIGEN,
            url_afectada=objetivo,
        ))

    # Atributo SameSite
    # SameSite se guarda en cookie._rest. Buscamos su valor sin importar
    # mayusculas.
    samesite = None
    for clave, valor in cookie._rest.items():
        if clave.lower() == "samesite":
            samesite = valor
            break

    if samesite is None:
        hallazgos.append(Hallazgo(
            titulo=f"Cookie sin atributo SameSite: {nombre}",
            categoria="A04",
            severidad="baja",
            descripcion=(
                f"La cookie '{nombre}' no define el atributo SameSite. Sin el, "
                f"la cookie se envia en peticiones desde otros sitios, lo que "
                f"facilita ataques de tipo Cross-Site Request Forgery (CSRF)."
            ),
            cvss=3.1,
            evidencia=f"Set-Cookie: {nombre} (sin atributo 'SameSite')",
            recomendacion=(
                "Definir SameSite=Lax (o Strict para cookies sensibles) segun "
                "el comportamiento requerido."
            ),
            herramienta_origen=ORIGEN,
            url_afectada=objetivo,
        ))
    elif samesite.lower() == "none":
        # SameSite=None es valido pero debe ir siempre con Secure y es la
        # opcion mas permisiva: la señalamos como informativa.
        hallazgos.append(Hallazgo(
            titulo=f"Cookie con SameSite=None: {nombre}",
            categoria="A04",
            severidad="informativa",
            descripcion=(
                f"La cookie '{nombre}' usa SameSite=None, el valor mas "
                f"permisivo (se envia en contextos de terceros). Debe ir "
                f"siempre acompañado del flag Secure y usarse solo si es "
                f"estrictamente necesario."
            ),
            cvss=None,
            evidencia=f"Set-Cookie: {nombre}; SameSite=None",
            recomendacion=(
                "Usar SameSite=Lax o Strict salvo que el flujo requiera "
                "explicitamente cookies de terceros."
            ),
            herramienta_origen=ORIGEN,
            url_afectada=objetivo,
        ))

    return hallazgos


def ejecutar(config: dict, logger: logging.Logger) -> list[Hallazgo]:
    """
    Punto de entrada del modulo (lo llama main.py).

    Hace una peticion GET a la URL objetivo, recorre las cookies que el
    servidor haya establecido (Set-Cookie) y revisa sus flags de seguridad.

    Devuelve lista vacia si no hay cookies, si todas estan bien configuradas
    o si no se pudo conectar.
    """
    objetivo = config["objetivo"]["url"].strip()
    opciones = config.get("opciones", {})
    timeout = opciones.get("timeout", 10)
    verificar_ssl = opciones.get("verificar_ssl", True)
    user_agent = opciones.get("user_agent", "AuditoriaWeb/1.0")

    logger.info(f"[cookies] Analizando cookies de {objetivo}")

    hallazgos: list[Hallazgo] = []

    try:
        respuesta = requests.get(
            objetivo,
            timeout=timeout,
            verify=verificar_ssl,
            headers={"User-Agent": user_agent},
            allow_redirects=True,
        )
    except requests.exceptions.SSLError as e:
        logger.error(
            f"[cookies] Error SSL al conectar. Si el objetivo usa un "
            f"certificado autofirmado, pon verificar_ssl: false en config.yaml. "
            f"Detalle: {e}"
        )
        return hallazgos
    except requests.exceptions.RequestException as e:
        logger.error(f"[cookies] No se pudo conectar con {objetivo}: {e}")
        return hallazgos

    # respuesta.cookies es un RequestsCookieJar iterable de objetos cookie.
    cookies = list(respuesta.cookies)

    if not cookies:
        logger.info("[cookies] El servidor no establecio ninguna cookie.")
        return hallazgos

    logger.info(f"[cookies] {len(cookies)} cookie(s) encontrada(s).")

    for cookie in cookies:
        hallazgos_cookie = _analizar_cookie(cookie, objetivo)
        hallazgos.extend(hallazgos_cookie)
        if hallazgos_cookie:
            logger.info(
                f"[cookies] '{cookie.name}': "
                f"{len(hallazgos_cookie)} problema(s) de configuracion."
            )
        else:
            logger.info(f"[cookies] '{cookie.name}': flags correctos.")

    logger.info(
        f"[cookies] Analisis terminado. {len(hallazgos)} hallazgo(s) en total."
    )

    return hallazgos


# Prueba independiente:
#     python3 -m modulos.cookies
# Se usa httpbin, que permite pedir que el servidor establezca una cookie
# de prueba sin flags, para comprobar que el modulo la detecta.
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    log = logging.getLogger("prueba")

    # httpbin.org/cookies/set/NOMBRE/VALOR establece una cookie sin flags.
    config_prueba = {
        "objetivo": {"url": "https://httpbin.org/cookies/set/sesion/abc123"},
        "opciones": {"timeout": 15, "verificar_ssl": True},
    }

    print("Probando el modulo cookies contra httpbin.org ...\n")
    resultados = ejecutar(config_prueba, log)

    print(f"\nSe generaron {len(resultados)} hallazgos:\n")
    for h in resultados:
        print(h)
        print()