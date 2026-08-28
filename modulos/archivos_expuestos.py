"""
archivos_expuestos.py  (modulo de deteccion - A02: Security Misconfiguration)
Busca archivos y directorios sensibles que no deberian ser accesibles
publicamente. Por cada uno que responda como accesible, genera un Hallazgo.

Rutas que revisa (entre otras):
  - .git/HEAD, .git/config : repositorio Git expuesto (permite descargar el
                             codigo fuente completo).
  - .env                   : variables de entorno (suelen contener claves,
                             credenciales de base de datos, tokens).
  - backups y dumps        : copias de seguridad o volcados de BD accesibles.
  - archivos de config     : wp-config.php, config.php, etc.
  - listado de directorios : carpetas que muestran su contenido.

EL RETO DE ESTE MODULO: evitar FALSOS POSITIVOS. Muchos servidores devuelven
una pagina (codigo 200) para CUALQUIER ruta, aunque el archivo no exista
(tipico en aplicaciones de una sola pagina / SPA, o en paginas 404
personalizadas que responden 200). Para no reportar archivos que en realidad
no existen, el modulo:

  1. Primero pide una ruta ALEATORIA que seguro no existe, y guarda como es
     la respuesta "de archivo inexistente" (su tamaño y un fragmento).
  2. Luego, al probar cada ruta sensible, la compara con esa referencia.
     Si la respuesta es identica a la de "no existe", NO la reporta.
  3. Ademas valida el CONTENIDO: por ejemplo, .git/HEAD solo se reporta si
     su contenido realmente parece el de un HEAD de Git.

Patron de siempre:
    def ejecutar(config, logger) -> list[Hallazgo]
"""

import logging
import random
import string
from urllib.parse import urljoin

import requests

from core.modelo_hallazgo import Hallazgo


ORIGEN = "modulo_archivos_expuestos"


# Rutas sensibles a comprobar.
# Cada entrada define:
#   ruta          : el path relativo a probar.
#   titulo        : nombre del hallazgo.
#   severidad     : gravedad si se encuentra expuesto.
#   cvss          : puntuacion.
#   descripcion   : que es y por que es peligroso.
#   recomendacion : como corregirlo.
#   firma         : (opcional) texto que DEBE aparecer en el contenido para
#                   confirmar que es realmente ese archivo (anti falso positivo).
# -----------------------------------------------------------------------------
RUTAS_SENSIBLES = [
    {
        "ruta": ".git/HEAD",
        "titulo": "Repositorio Git expuesto (.git/HEAD accesible)",
        "severidad": "alta",
        "cvss": 7.5,
        "descripcion": (
            "El directorio .git es accesible publicamente. Un atacante puede "
            "descargar el historial completo del repositorio y con el, todo el "
            "codigo fuente de la aplicacion, incluyendo posibles credenciales."
        ),
        "recomendacion": (
            "Bloquear el acceso al directorio .git desde el servidor web o "
            "eliminarlo del directorio publico de despliegue."
        ),
        "firma": "ref:",  # un .git/HEAD real contiene "ref: refs/heads/..."
    },
    {
        "ruta": ".git/config",
        "titulo": "Configuracion de Git expuesta (.git/config accesible)",
        "severidad": "alta",
        "cvss": 7.5,
        "descripcion": (
            "El archivo .git/config es accesible. Revela la configuracion del "
            "repositorio y, a menudo, URLs remotas que pueden contener "
            "informacion sensible."
        ),
        "recomendacion": "Bloquear el acceso al directorio .git.",
        "firma": "[core]",  # un .git/config real contiene la seccion [core]
    },
    {
        "ruta": ".env",
        "titulo": "Archivo .env expuesto",
        "severidad": "critica",
        "cvss": 9.1,
        "descripcion": (
            "El archivo .env es accesible publicamente. Este archivo suele "
            "contener credenciales de base de datos, claves de API, secretos de "
            "aplicacion y otros datos altamente sensibles."
        ),
        "recomendacion": (
            "Mover el archivo .env fuera del directorio publico y bloquear su "
            "acceso desde el servidor web. Rotar cualquier credencial expuesta."
        ),
        "firma": "=",  # un .env real tiene lineas tipo CLAVE=valor
    },
    {
        "ruta": "config.php",
        "titulo": "Archivo config.php accesible",
        "severidad": "media",
        "cvss": 5.3,
        "descripcion": (
            "Existe un archivo config.php accesible. Si el servidor no procesa "
            "PHP correctamente, su contenido (con credenciales) podria quedar "
            "expuesto."
        ),
        "recomendacion": (
            "Asegurar que los archivos .php se procesen y no se sirvan como "
            "texto; mover la configuracion fuera del directorio publico."
        ),
        "firma": None,  # dificil de confirmar por contenido; se valida por 200 real
    },
    {
        "ruta": "backup.zip",
        "titulo": "Copia de seguridad accesible (backup.zip)",
        "severidad": "alta",
        "cvss": 7.5,
        "descripcion": (
            "Existe un archivo de copia de seguridad accesible publicamente. "
            "Puede contener el codigo fuente completo o volcados de la base de "
            "datos."
        ),
        "recomendacion": (
            "Eliminar las copias de seguridad del directorio publico y "
            "almacenarlas en una ubicacion no accesible desde la web."
        ),
        "firma": None,
    },
    {
        "ruta": "backup.sql",
        "titulo": "Volcado de base de datos accesible (backup.sql)",
        "severidad": "critica",
        "cvss": 9.1,
        "descripcion": (
            "Existe un volcado SQL accesible publicamente. Puede contener toda "
            "la base de datos, incluyendo usuarios, contraseñas y datos "
            "personales."
        ),
        "recomendacion": (
            "Eliminar el volcado del directorio publico de inmediato y rotar "
            "credenciales si estuvieron expuestas."
        ),
        "firma": None,
    },
    {
        "ruta": ".htaccess",
        "titulo": "Archivo .htaccess accesible",
        "severidad": "baja",
        "cvss": 3.1,
        "descripcion": (
            "El archivo .htaccess es accesible. Puede revelar reglas de "
            "reescritura, rutas internas y detalles de la configuracion."
        ),
        "recomendacion": (
            "Configurar el servidor para denegar el acceso a archivos que "
            "empiezan por punto."
        ),
        "firma": None,
    },
    {
        "ruta": "phpinfo.php",
        "titulo": "Pagina phpinfo() accesible",
        "severidad": "media",
        "cvss": 5.3,
        "descripcion": (
            "Existe una pagina phpinfo() accesible. Revela la configuracion "
            "completa de PHP, rutas del sistema, modulos y variables de entorno."
        ),
        "recomendacion": "Eliminar los archivos phpinfo() del entorno de produccion.",
        "firma": "phpinfo",
    },
]

# Directorios cuyo listado queremos comprobar (que no muestren su contenido).
DIRECTORIOS_LISTADO = ["uploads/", "images/", "backup/", "files/", "admin/"]

# Frases tipicas en una pagina de "listado de directorio" de un servidor.
INDICIOS_LISTADO = ["index of /", "directory listing for", "<title>index of"]


def _ruta_aleatoria() -> str:
    """Genera un nombre de ruta aleatorio que casi con seguridad no existe."""
    aleatorio = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
    return f"{aleatorio}-noexiste.html"


def _pedir(url, opciones, logger):
    """Hace un GET seguro y devuelve la respuesta, o None si falla."""
    try:
        return requests.get(
            url,
            timeout=opciones.get("timeout", 10),
            verify=opciones.get("verificar_ssl", True),
            headers={"User-Agent": opciones.get("user_agent", "AuditoriaWeb/1.0")},
            allow_redirects=False,  # no seguir redirecciones: nos interesa la ruta exacta
        )
    except requests.exceptions.RequestException as e:
        logger.debug(f"[archivos_expuestos] Fallo al pedir {url}: {e}")
        return None


def ejecutar(config: dict, logger: logging.Logger) -> list[Hallazgo]:
    """
    Punto de entrada del modulo (lo llama main.py).

    Estrategia anti-falsos-positivos:
      1. Establece una "linea base" pidiendo una ruta que no existe.
      2. Prueba cada ruta sensible y la compara con esa linea base.
      3. Valida el contenido con la 'firma' cuando esta definida.
    """
    objetivo = config["objetivo"]["url"].strip()
    if not objetivo.endswith("/"):
        objetivo += "/"
    opciones = config.get("opciones", {})

    logger.info(f"[archivos_expuestos] Buscando archivos sensibles en {objetivo}")

    hallazgos: list[Hallazgo] = []

    # --- Paso 1: linea base con una ruta inexistente ---
    url_base_falsa = urljoin(objetivo, _ruta_aleatoria())
    resp_falsa = _pedir(url_base_falsa, opciones, logger)

    if resp_falsa is None:
        logger.error(
            "[archivos_expuestos] No se pudo conectar con el objetivo. "
            "Se omite el modulo."
        )
        return hallazgos

    # Como responde el servidor a algo que NO existe.
    codigo_inexistente = resp_falsa.status_code
    long_inexistente = len(resp_falsa.content)
    logger.info(
        f"[archivos_expuestos] Linea base: una ruta inexistente responde "
        f"HTTP {codigo_inexistente} ({long_inexistente} bytes)."
    )

    #Paso 2 probar cada ruta sensible
    for item in RUTAS_SENSIBLES:
        url = urljoin(objetivo, item["ruta"])
        resp = _pedir(url, opciones, logger)
        if resp is None:
            continue

        # Solo nos interesan respuestas 200 (accesible).
        if resp.status_code != 200:
            logger.debug(
                f"[archivos_expuestos] {item['ruta']}: HTTP {resp.status_code} "
                f"(no accesible)."
            )
            continue

        # ¿La respuesta es sospechosamente igual a la de "no existe"?
        # Si el servidor respondio 200 tambien a la ruta falsa y con tamaño
        # parecido, casi seguro es una pagina generica (SPA / 404 como 200).
        if codigo_inexistente == 200:
            diferencia = abs(len(resp.content) - long_inexistente)
            if diferencia < 50:  # tamaños casi iguales -> misma pagina generica
                logger.debug(
                    f"[archivos_expuestos] {item['ruta']}: responde 200 pero "
                    f"identico a la pagina generica. Se descarta (falso positivo)."
                )
                continue

        # Validacion por firma de contenido (si esta definida).
        firma = item.get("firma")
        if firma is not None:
            contenido = resp.text[:2000].lower()
            if firma.lower() not in contenido:
                logger.debug(
                    f"[archivos_expuestos] {item['ruta']}: responde 200 pero el "
                    f"contenido no coincide con la firma esperada "
                    f"('{firma}'). Se descarta."
                )
                continue

        # Si llegamos aqui, es un hallazgo real.
        hallazgos.append(Hallazgo(
            titulo=item["titulo"],
            categoria="A02",
            severidad=item["severidad"],
            descripcion=item["descripcion"],
            cvss=item["cvss"],
            evidencia=(
                f"GET {url} -> HTTP 200 ({len(resp.content)} bytes). "
                f"Recurso accesible publicamente."
            ),
            recomendacion=item["recomendacion"],
            herramienta_origen=ORIGEN,
            url_afectada=url,
        ))
        logger.info(f"[archivos_expuestos] EXPUESTO: {item['ruta']}")

    # Paso 3: comprobar listado de directorios
    for directorio in DIRECTORIOS_LISTADO:
        url = urljoin(objetivo, directorio)
        resp = _pedir(url, opciones, logger)
        if resp is None or resp.status_code != 200:
            continue

        contenido = resp.text[:3000].lower()
        if any(indicio in contenido for indicio in INDICIOS_LISTADO):
            hallazgos.append(Hallazgo(
                titulo=f"Listado de directorio habilitado: {directorio}",
                categoria="A02",
                severidad="media",
                descripcion=(
                    f"El directorio '{directorio}' muestra el listado de su "
                    f"contenido. Esto revela archivos internos y facilita a un "
                    f"atacante descubrir recursos sensibles."
                ),
                cvss=5.3,
                evidencia=f"GET {url} -> muestra un listado de directorio.",
                recomendacion=(
                    "Deshabilitar el listado de directorios en el servidor "
                    "(por ejemplo 'Options -Indexes' en Apache)."
                ),
                herramienta_origen=ORIGEN,
                url_afectada=url,
            ))
            logger.info(f"[archivos_expuestos] Listado habilitado: {directorio}")

    logger.info(
        f"[archivos_expuestos] Analisis terminado. {len(hallazgos)} hallazgo(s)."
    )
    return hallazgos


# Prueba independiente:
#     python3 -m modulos.archivos_expuestos
# Se apoya en un servidor local de prueba que se lanza aparte.
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    log = logging.getLogger("prueba")

    config_prueba = {
        "objetivo": {"url": "http://127.0.0.1:8099/"},
        "opciones": {"timeout": 5, "verificar_ssl": False},
    }

    print("Probando el modulo archivos_expuestos ...")
    print("(Necesita un servidor de prueba corriendo en el puerto 8099)\n")
    resultados = ejecutar(config_prueba, log)

    print(f"\nSe generaron {len(resultados)} hallazgos:\n")
    for h in resultados:
        print(h)
        print()