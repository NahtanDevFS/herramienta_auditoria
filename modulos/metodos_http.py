"""
metodos_http.py  (modulo de deteccion - A01: Broken Access Control)
Comprueba dos problemas relacionados con el control de acceso:

  1. METODOS HTTP PELIGROSOS habilitados:
     - PUT / DELETE : permiten subir o borrar archivos si no estan protegidos.
     - TRACE        : puede facilitar ataques de Cross-Site Tracing (XST).
     - CONNECT      : puede permitir usar el servidor como proxy.
     El modulo pregunta al servidor que metodos permite (via OPTIONS) y ademas
     prueba activamente algunos para confirmar.

  2. PATH TRAVERSAL:
     Intenta acceder a archivos del sistema fuera del directorio web usando
     secuencias como '../../../etc/passwd'. Si el servidor los devuelve, es
     vulnerable.

Patron de siempre:
    def ejecutar(config, logger) -> list[Hallazgo]
"""

import logging
from urllib.parse import urljoin, urlparse

import requests

from core.modelo_hallazgo import Hallazgo


ORIGEN = "modulo_metodos_http"

# Metodos peligrosos y su severidad si estan habilitados.
METODOS_PELIGROSOS = {
    "PUT": ("alta", 7.5,
            "El metodo PUT permite subir archivos al servidor. Si no esta "
            "correctamente restringido, un atacante podria subir codigo "
            "malicioso (webshells)."),
    "DELETE": ("alta", 7.5,
               "El metodo DELETE permite borrar recursos del servidor. Sin la "
               "proteccion adecuada, un atacante podria eliminar archivos."),
    "TRACE": ("media", 5.3,
              "El metodo TRACE esta habilitado y puede facilitar ataques de "
              "Cross-Site Tracing (XST), exponiendo cabeceras sensibles."),
    "CONNECT": ("media", 5.3,
                "El metodo CONNECT puede permitir que el servidor sea usado "
                "como proxy hacia otros destinos."),
    "PATCH": ("media", 5.3,
              "El metodo PATCH permite modificar recursos. Verificar que este "
              "correctamente controlado."),
}

# Cargas de path traversal a probar y el patron que confirmaria el exito.
PAYLOADS_TRAVERSAL = [
    "../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",       # codificado
    "....//....//....//etc/passwd",            # doble punto
    "../../../../windows/win.ini",             # equivalente en Windows
]
# Firmas que confirman que se leyo un archivo del sistema.
FIRMAS_TRAVERSAL = {
    "etc/passwd": "root:",           # /etc/passwd empieza con "root:"
    "win.ini": "[",                  # win.ini contiene secciones [xxx]
}


def ejecutar(config: dict, logger: logging.Logger) -> list[Hallazgo]:
    """
    Punto de entrada del modulo (lo llama main.py).

    Comprueba metodos HTTP peligrosos y prueba path traversal en el objetivo.
    """
    objetivo = config["objetivo"]["url"].strip()
    opciones = config.get("opciones", {})
    timeout = opciones.get("timeout", 10)
    verificar_ssl = opciones.get("verificar_ssl", True)
    user_agent = opciones.get("user_agent", "AuditoriaWeb/1.0")

    logger.info(f"[metodos_http] Analizando metodos HTTP de {objetivo}")

    hallazgos: list[Hallazgo] = []
    headers = {"User-Agent": user_agent}

    #Parte 1: metodos peligrosos
    hallazgos.extend(
        _revisar_metodos(objetivo, headers, timeout, verificar_ssl, logger)
    )

    #Parte 2: path traversal
    hallazgos.extend(
        _probar_path_traversal(objetivo, headers, timeout, verificar_ssl, logger)
    )

    logger.info(
        f"[metodos_http] Analisis terminado. {len(hallazgos)} hallazgo(s)."
    )
    return hallazgos


def _revisar_metodos(objetivo, headers, timeout, verificar_ssl, logger):
    """Consulta con OPTIONS que metodos permite el servidor y los evalua."""
    hallazgos = []

    # 1. Preguntar via OPTIONS que metodos declara el servidor.
    metodos_declarados = set()
    try:
        resp = requests.options(
            objetivo, headers=headers, timeout=timeout, verify=verificar_ssl
        )
        allow = resp.headers.get("Allow", "")
        if allow:
            metodos_declarados = {m.strip().upper() for m in allow.split(",")}
            logger.info(f"[metodos_http] El servidor declara (Allow): {allow}")
    except requests.exceptions.RequestException as e:
        logger.debug(f"[metodos_http] OPTIONS fallo: {e}")

    # 2. Evaluar cada metodo peligroso que el servidor declare permitir.
    for metodo, (severidad, cvss, descripcion) in METODOS_PELIGROSOS.items():
        if metodo not in metodos_declarados:
            continue

        # Confirmacion activa para TRACE (es seguro de probar).
        confirmado = ""
        if metodo == "TRACE":
            try:
                r = requests.request(
                    "TRACE", objetivo, headers=headers,
                    timeout=timeout, verify=verificar_ssl
                )
                if r.status_code == 200 and "TRACE" in r.text:
                    confirmado = " (confirmado activamente)"
            except requests.exceptions.RequestException:
                pass

        hallazgos.append(Hallazgo(
            titulo=f"Metodo HTTP peligroso habilitado: {metodo}",
            categoria="A01",
            severidad=severidad,
            descripcion=descripcion + confirmado,
            cvss=cvss,
            evidencia=(
                f"El servidor declara permitir el metodo {metodo} en la "
                f"cabecera Allow de la respuesta OPTIONS."
            ),
            recomendacion=(
                f"Deshabilitar el metodo {metodo} si no es necesario, o "
                f"restringir su uso a usuarios autenticados y autorizados."
            ),
            herramienta_origen=ORIGEN,
            url_afectada=objetivo,
        ))
        logger.info(f"[metodos_http] Metodo peligroso declarado: {metodo}")

    return hallazgos


def _probar_path_traversal(objetivo, headers, timeout, verificar_ssl, logger):
    """Intenta leer archivos del sistema mediante secuencias de path traversal."""
    hallazgos = []

    # Probaremos los payloads sobre la ruta base del objetivo.
    base = objetivo if objetivo.endswith("/") else objetivo + "/"

    for payload in PAYLOADS_TRAVERSAL:
        url = urljoin(base, payload)
        try:
            resp = requests.get(
                url, headers=headers, timeout=timeout,
                verify=verificar_ssl, allow_redirects=False
            )
        except requests.exceptions.RequestException as e:
            logger.debug(f"[metodos_http] Traversal fallo en {url}: {e}")
            continue

        if resp.status_code != 200:
            continue

        # ¿El contenido coincide con la firma de un archivo del sistema?
        contenido = resp.text[:3000]
        for clave, firma in FIRMAS_TRAVERSAL.items():
            if clave in payload.lower() and firma in contenido:
                hallazgos.append(Hallazgo(
                    titulo="Path Traversal / Local File Inclusion",
                    categoria="A01",
                    severidad="critica",
                    descripcion=(
                        "El servidor es vulnerable a path traversal: es posible "
                        "leer archivos del sistema fuera del directorio web "
                        "manipulando la ruta. Un atacante podria acceder a "
                        "archivos de configuracion, credenciales o codigo fuente."
                    ),
                    cvss=9.1,
                    evidencia=(
                        f"GET {url} devolvio contenido de un archivo del sistema "
                        f"(coincide con la firma '{firma}')."
                    ),
                    recomendacion=(
                        "Validar y sanitizar las rutas de archivo. Nunca "
                        "construir rutas con entrada del usuario sin validar. "
                        "Usar rutas canonicas y listas blancas."
                    ),
                    herramienta_origen=ORIGEN,
                    url_afectada=url,
                ))
                logger.info(f"[metodos_http] PATH TRAVERSAL detectado en {url}")
                # Un hallazgo confirmado basta; no seguimos con mas payloads.
                return hallazgos

    logger.info("[metodos_http] No se detecto path traversal.")
    return hallazgos


# Prueba independiente:
#     python3 -m modulos.metodos_http
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    log = logging.getLogger("prueba")

    config_prueba = {
        "objetivo": {"url": "http://scanme.nmap.org"},
        "opciones": {"timeout": 10, "verificar_ssl": True},
    }

    print("Probando el modulo metodos_http contra scanme.nmap.org ...\n")
    resultados = ejecutar(config_prueba, log)

    print(f"\nSe generaron {len(resultados)} hallazgos:\n")
    for h in resultados:
        print(h)
        print(f"    Evidencia: {h.evidencia}")
        print()
    if not resultados:
        print("(Sin hallazgos: no se detectaron metodos peligrosos ni traversal.)")