"""
cabeceras_http.py  (modulo de deteccion - A02: Security Misconfiguration)
Revisa las cabeceras HTTP de seguridad que debe enviar un servidor web bien
configurado. Por cada cabecera recomendada que falte (o este mal puesta),
genera un objeto Hallazgo.

Es el primer modulo "real" del proyecto y sirve de PLANTILLA para los demas:
todos los modulos de deteccion seguiran esta misma forma:

    def ejecutar(config, logger) -> list[Hallazgo]:
        ... hace su trabajo ...
        return lista_de_hallazgos

El orquestador (main.py) llama a 'ejecutar', recoge la lista devuelta y la
suma al reporte. Ningun modulo guarda nada por su cuenta: solo detecta y
devuelve hallazgos.

Cabeceras que revisamos y por que importan:
  - Content-Security-Policy      : mitiga XSS e inyeccion de contenido.
  - Strict-Transport-Security    : fuerza HTTPS (evita downgrade a HTTP).
  - X-Frame-Options              : evita clickjacking (embeber la web en iframe).
  - X-Content-Type-Options       : evita que el navegador "adivine" tipos MIME.
  - Referrer-Policy              : controla que info de referencia se filtra.
  - Permissions-Policy           : limita APIs del navegador (camara, micro...).
"""

import logging

import requests

# Import del modelo. Al ejecutarse via main.py (modo paquete), la ruta es
# 'core.modelo_hallazgo'. Ver nota al final sobre como probar el modulo solo.
from core.modelo_hallazgo import Hallazgo


# Nombre con el que este modulo se identifica en los hallazgos.
ORIGEN = "modulo_cabeceras_http"


# Definicion de las cabeceras a revisar.
# Cada entrada describe: severidad si falta, descripcion, recomendacion y CVSS.
# Tener esto como datos (y no como codigo repetido) hace facil añadir mas.
CABECERAS_SEGURIDAD = {
    "Content-Security-Policy": {
        "severidad": "alta",
        "cvss": 6.5,
        "descripcion": (
            "No se envia la cabecera Content-Security-Policy (CSP). Sin ella, "
            "el navegador no restringe el origen de scripts y recursos, lo que "
            "facilita ataques de Cross-Site Scripting (XSS) e inyeccion de "
            "contenido."
        ),
        "recomendacion": (
            "Definir una politica CSP restrictiva, empezando por "
            "\"default-src 'self'\" y ajustandola a las necesidades del sitio."
        ),
    },
    "Strict-Transport-Security": {
        "severidad": "media",
        "cvss": 5.3,
        "descripcion": (
            "Falta la cabecera Strict-Transport-Security (HSTS). Sin ella, un "
            "atacante puede intentar forzar la conexion por HTTP en texto claro "
            "(ataques de downgrade / man-in-the-middle)."
        ),
        "recomendacion": (
            "Enviar 'Strict-Transport-Security: max-age=31536000; "
            "includeSubDomains' en todas las respuestas HTTPS."
        ),
    },
    "X-Frame-Options": {
        "severidad": "media",
        "cvss": 4.3,
        "descripcion": (
            "Falta la cabecera X-Frame-Options. Sin ella, la pagina puede ser "
            "embebida en un iframe de otro sitio, habilitando ataques de "
            "clickjacking."
        ),
        "recomendacion": (
            "Enviar 'X-Frame-Options: DENY' o 'SAMEORIGIN', o bien usar la "
            "directiva frame-ancestors en la CSP."
        ),
    },
    "X-Content-Type-Options": {
        "severidad": "baja",
        "cvss": 3.1,
        "descripcion": (
            "Falta la cabecera X-Content-Type-Options. Sin ella, el navegador "
            "puede intentar adivinar (MIME-sniffing) el tipo de contenido, lo "
            "que puede derivar en la ejecucion de contenido no deseado."
        ),
        "recomendacion": "Enviar 'X-Content-Type-Options: nosniff'.",
    },
    "Referrer-Policy": {
        "severidad": "baja",
        "cvss": 2.6,
        "descripcion": (
            "Falta la cabecera Referrer-Policy. Sin ella, el navegador puede "
            "enviar la URL completa de origen a otros sitios, filtrando posible "
            "informacion sensible en el parametro Referer."
        ),
        "recomendacion": (
            "Enviar 'Referrer-Policy: no-referrer' o "
            "'strict-origin-when-cross-origin'."
        ),
    },
    "Permissions-Policy": {
        "severidad": "baja",
        "cvss": 2.6,
        "descripcion": (
            "Falta la cabecera Permissions-Policy. Sin ella no se restringe el "
            "acceso a APIs potentes del navegador (camara, microfono, "
            "geolocalizacion), ampliando la superficie de ataque."
        ),
        "recomendacion": (
            "Definir una Permissions-Policy que desactive las APIs no usadas, "
            "por ejemplo 'geolocation=(), camera=(), microphone=()'."
        ),
    },
}


def ejecutar(config: dict, logger: logging.Logger) -> list[Hallazgo]:
    """
    Punto de entrada del modulo (lo llama main.py).

    Hace una peticion GET a la URL objetivo, examina las cabeceras de la
    respuesta y devuelve una lista de Hallazgo por cada cabecera de seguridad
    ausente.

    Devuelve lista vacia si la web tiene todas las cabeceras o si no se pudo
    conectar (el error se registra en el log).
    """
    objetivo = config["objetivo"]["url"].strip()
    opciones = config.get("opciones", {})
    timeout = opciones.get("timeout", 10)
    verificar_ssl = opciones.get("verificar_ssl", True)
    user_agent = opciones.get("user_agent", "AuditoriaWeb/1.0")

    logger.info(f"[cabeceras_http] Analizando cabeceras de {objetivo}")

    hallazgos: list[Hallazgo] = []

    # Peticion HTTP con manejo de errores 
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
            f"[cabeceras_http] Error SSL al conectar. Si el objetivo usa un "
            f"certificado autofirmado, pon verificar_ssl: false en config.yaml. "
            f"Detalle: {e}"
        )
        return hallazgos
    except requests.exceptions.RequestException as e:
        logger.error(f"[cabeceras_http] No se pudo conectar con {objetivo}: {e}")
        return hallazgos

    # Las claves de las cabeceras en requests son insensibles a mayusculas,
    # asi que podemos consultarlas directamente por su nombre.
    cabeceras_presentes = respuesta.headers

    #Revisar cada cabecera de seguridad
    for nombre, info in CABECERAS_SEGURIDAD.items():
        if nombre not in cabeceras_presentes:
            hallazgos.append(Hallazgo(
                titulo=f"Falta la cabecera de seguridad: {nombre}",
                categoria="A02",
                severidad=info["severidad"],
                descripcion=info["descripcion"],
                cvss=info["cvss"],
                evidencia=(
                    f"GET {objetivo} (HTTP {respuesta.status_code}) -> la "
                    f"respuesta no incluye la cabecera '{nombre}'."
                ),
                recomendacion=info["recomendacion"],
                herramienta_origen=ORIGEN,
                url_afectada=objetivo,
            ))
            logger.info(f"[cabeceras_http] Ausente: {nombre}")
        else:
            logger.debug(
                f"[cabeceras_http] Presente: {nombre} = "
                f"{cabeceras_presentes[nombre]}"
            )

    logger.info(
        f"[cabeceras_http] Analisis terminado. "
        f"{len(hallazgos)} cabecera(s) de seguridad ausente(s)."
    )

    return hallazgos


# Prueba independiente del modulo.
# Como este archivo importa 'core.modelo_hallazgo', para probarlo solo hay
# que ejecutarlo desde la raiz del proyecto asi:
#     python3 -m modulos.cabeceras_http
# Esto usa una config minima y una web publica real de ejemplo.
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    log = logging.getLogger("prueba")

    config_prueba = {
        "objetivo": {"url": "http://example.com"},
        "opciones": {"timeout": 10, "verificar_ssl": True},
    }

    print("Probando el modulo cabeceras_http contra http://example.com ...\n")
    resultados = ejecutar(config_prueba, log)

    print(f"\nSe generaron {len(resultados)} hallazgos:\n")
    for h in resultados:
        print(h)
        print()