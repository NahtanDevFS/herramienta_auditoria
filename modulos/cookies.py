# modulo de deteccion: verifica flags de seguridad en cookies y genera hallazgos

import logging

import requests

from core.modelo_hallazgo import Hallazgo


ORIGEN = "modulo_cookies"


def _analizar_cookie(cookie, objetivo: str) -> list[Hallazgo]:
    # analiza una cookie y devuelve los hallazgos de los flags que le falten
    # 'cookie' es un objeto del cookiejar de requests
    hallazgos: list[Hallazgo] = []
    nombre = cookie.name

    # flag secure
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

    # flag httponly (buscamos en atributos no estandar)
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

    # atributo samesite (buscamos en atributos no estandar)
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
        # samesite=none es valido pero debe ir siempre con secure informativo
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
    # punto de entrada del modulo (lo llama main py)
    # hace peticion get y revisa los flags de las cookies establecidas
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

    # respuesta cookies es un requestscookiejar iterable de objetos cookie
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


# prueba unitaria independiente usando httpbin para detectar cookies sin flags
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    log = logging.getLogger("prueba")

    # httpbin org/cookies/set/nombre/valor establece una cookie sin flags
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