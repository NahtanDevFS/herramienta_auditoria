# Detecta SUSCEPTIBILIDAD a un downgrade HTTPS -> HTTP (A02/A04).
#
# Aclaracion importante de alcance: esta herramienta NO ejecuta un ataque de
# SSL-stripping. Ejecutarlo requiere una posicion de red intermedia
# (man-in-the-middle) entre la victima y el servidor, algo que un escaner web no
# hace. Lo que SI se puede (y es lo correcto para una auditoria) es detectar si
# el sitio es VULNERABLE a que lo fuercen a HTTP en texto claro, revisando tres
# senales estandar:
#   1) La version HTTP no redirige a HTTPS (se puede navegar en claro).
#   2) Falta HSTS (Strict-Transport-Security), el mecanismo que impide el
#      downgrade en el navegador.
#   3) Contenido mixto: la pagina HTTPS carga recursos por http:// (se pueden
#      interceptar y sirven de punto de entrada para el downgrade).

import logging
import re
from urllib.parse import urlparse

import requests

from core.modelo_hallazgo import Hallazgo

ORIGEN = "modulo_transporte_https"

# recursos http:// embebidos en un documento (src/href hacia texto claro)
_MIXTO_RE = re.compile(r"""(?:src|href)\s*=\s*['"]\s*(http://[^'"]+)""", re.I)


def ejecutar(config: dict, logger: logging.Logger) -> list[Hallazgo]:
    objetivo = config["objetivo"]["url"].strip()
    opciones = config.get("opciones", {})
    timeout = opciones.get("timeout", 10)
    verificar_ssl = opciones.get("verificar_ssl", True)
    user_agent = opciones.get("user_agent", "AuditoriaWeb/1.0")

    parsed = urlparse(objetivo)
    hallazgos: list[Hallazgo] = []

    # el analisis de downgrade solo tiene sentido si el objetivo se sirve por HTTPS
    if parsed.scheme != "https":
        logger.info(
            "[transporte_https] El objetivo no usa HTTPS; el analisis de "
            "downgrade no aplica. Se omite este modulo."
        )
        return hallazgos

    cabeceras = {"User-Agent": user_agent}
    url_http = objetivo.replace("https://", "http://", 1)

    logger.info(f"[transporte_https] Comprobando susceptibilidad a downgrade en {objetivo}")

    # --- 1) la version HTTP no redirige a HTTPS ---
    try:
        r_http = requests.get(
            url_http, timeout=timeout, verify=verificar_ssl,
            headers=cabeceras, allow_redirects=True,
        )
        # url final tras seguir redirecciones
        destino_final = urlparse(r_http.url)
        if destino_final.scheme != "https":
            hallazgos.append(Hallazgo(
                titulo="El sitio se puede navegar por HTTP sin redirigir a HTTPS",
                categoria="A02",
                severidad="media",
                descripcion=(
                    "Al solicitar la version HTTP del sitio, el servidor responde "
                    "en texto claro sin redirigir a HTTPS. Esto lo hace susceptible "
                    "a un ataque de downgrade (SSL-stripping): un atacante en "
                    "posicion de red puede mantener a la victima en HTTP e "
                    "interceptar credenciales y sesiones."
                ),
                cvss=5.9,
                evidencia=(
                    f"GET {url_http} -> HTTP {r_http.status_code}, URL final "
                    f"'{r_http.url}' (se queda en HTTP, no redirige a HTTPS)."
                ),
                recomendacion=(
                    "Redirigir todo el trafico HTTP a HTTPS con un 301 permanente "
                    "y activar HSTS para que el navegador nunca vuelva a HTTP."
                ),
                herramienta_origen=ORIGEN,
                url_afectada=url_http,
            ))
            logger.info("[transporte_https] HTTP no redirige a HTTPS.")
    except requests.exceptions.RequestException as e:
        # que la version HTTP no conteste es lo deseable, no es un hallazgo
        logger.debug(f"[transporte_https] La version HTTP no respondio: {e}")

    # --- 2 y 3) sobre la respuesta HTTPS: HSTS y contenido mixto ---
    try:
        r_https = requests.get(
            objetivo, timeout=timeout, verify=verificar_ssl,
            headers=cabeceras, allow_redirects=True,
        )
    except requests.exceptions.RequestException as e:
        logger.error(f"[transporte_https] No se pudo conectar por HTTPS: {e}")
        return hallazgos

    # 2) HSTS ausente -> el navegador no impedira el downgrade.
    # Nota: el modulo cabeceras_http tambien avisa de HSTS ausente de forma
    # generica. Aqui lo enmarcamos especificamente en el riesgo de downgrade.
    if "Strict-Transport-Security" not in r_https.headers:
        hallazgos.append(Hallazgo(
            titulo="Sin HSTS: nada impide el downgrade a HTTP",
            categoria="A02",
            severidad="media",
            descripcion=(
                "La respuesta HTTPS no incluye Strict-Transport-Security (HSTS). "
                "HSTS es el mecanismo que ordena al navegador usar siempre HTTPS y "
                "rechazar HTTP en texto claro. Sin el, un atacante puede forzar la "
                "primera conexion por HTTP e iniciar un downgrade."
            ),
            cvss=5.3,
            evidencia=(
                f"GET {objetivo} (HTTP {r_https.status_code}) -> la respuesta no "
                f"incluye la cabecera 'Strict-Transport-Security'."
            ),
            recomendacion=(
                "Enviar 'Strict-Transport-Security: max-age=31536000; "
                "includeSubDomains; preload' en todas las respuestas HTTPS."
            ),
            herramienta_origen=ORIGEN,
            url_afectada=objetivo,
        ))
        logger.info("[transporte_https] HSTS ausente.")

    # 3) contenido mixto: recursos http:// dentro de la pagina HTTPS
    try:
        cuerpo = r_https.text or ""
    except Exception:
        cuerpo = ""
    recursos_mixtos = []
    for url_rec in _MIXTO_RE.findall(cuerpo):
        host_rec = urlparse(url_rec).hostname or ""
        # ignorar esquemas locales o de ejemplo que no son recursos reales
        if host_rec and host_rec not in ("localhost", "127.0.0.1", "example.com"):
            recursos_mixtos.append(url_rec)
    # dedup preservando orden
    vistos = set()
    recursos_mixtos = [u for u in recursos_mixtos if not (u in vistos or vistos.add(u))]

    if recursos_mixtos:
        muestra = "; ".join(recursos_mixtos[:5])
        hallazgos.append(Hallazgo(
            titulo="Contenido mixto: recursos cargados por HTTP en una pagina HTTPS",
            categoria="A02",
            severidad="baja",
            descripcion=(
                "La pagina servida por HTTPS incluye recursos (scripts, imagenes o "
                "enlaces) cargados por http:// en texto claro. Estos recursos se "
                "pueden interceptar y modificar en transito, y sirven de punto de "
                "entrada para forzar un downgrade de la sesion."
            ),
            cvss=3.7,
            evidencia=(
                f"{len(recursos_mixtos)} recurso(s) http:// en {objetivo}. "
                f"Ejemplos: {muestra}"
            ),
            recomendacion=(
                "Cargar todos los recursos por https:// y anadir la directiva CSP "
                "'upgrade-insecure-requests' para forzar el esquema seguro."
            ),
            herramienta_origen=ORIGEN,
            url_afectada=objetivo,
        ))
        logger.info(f"[transporte_https] Contenido mixto: {len(recursos_mixtos)} recurso(s).")

    logger.info(
        f"[transporte_https] Analisis terminado. {len(hallazgos)} hallazgo(s)."
    )
    return hallazgos


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    log = logging.getLogger("prueba")
    config_prueba = {
        "objetivo": {"url": "https://example.com"},
        "opciones": {"timeout": 10, "verificar_ssl": True},
    }
    print("Probando el modulo transporte_https contra https://example.com ...\n")
    for h in ejecutar(config_prueba, log):
        print(h)
        print()
