"""
tecnologias.py  (modulo de deteccion - A06: Vulnerable and Outdated Components)
Identifica las tecnologias que usa la web (servidor, lenguaje, framework, CMS,
librerias JS) y, cuando es posible, sus VERSIONES.

Por que importa (A06): conocer las versiones exactas es el primer paso para
saber si el objetivo usa componentes con vulnerabilidades conocidas (CVE). Este
modulo produce el inventario; el modulo de Nuclei (siguiente) lo complementa
cruzando versiones con CVEs.

Enfoque combinado (para maximizar la deteccion de versiones):
  1. Wappalyzer      -> inventario amplio de tecnologias (que hay).
  2. Cabeceras HTTP  -> versiones precisas de Server y X-Powered-By.
  3. Meta 'generator'-> version de CMS (WordPress, Joomla, etc.).

Genera:
  - Un Hallazgo informativo con el inventario completo (siempre).
  - Un Hallazgo por cada tecnologia cuya version este expuesta (util para A06),
    con severidad baja: exponer versiones facilita al atacante buscar exploits.

Patron de siempre:
    def ejecutar(config, logger) -> list[Hallazgo]
"""

import logging
import re
import warnings

import requests

from core.modelo_hallazgo import Hallazgo


ORIGEN = "modulo_tecnologias"


# -----------------------------------------------------------------------------
# Patrones para extraer libreria + version de las rutas de scripts y estilos.
# Los desarrolladores suelen dejar la version en el nombre del archivo o en la
# URL del CDN, lo que es una fuente de versiones muy fiable para A06.
# -----------------------------------------------------------------------------
PATRONES_JS = [
    # Archivo local con version: /js/jquery-3.6.0.min.js  o  angular.1.8.2.js
    re.compile(r"/([a-zA-Z0-9_\-\.]+?)[-\.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.(?:js|css)", re.I),
    # CDN estilo cdnjs: /ajax/libs/bootstrap/5.1.3/js/bootstrap.min.js
    re.compile(r"/libs?/([a-zA-Z0-9_\-\.]+)/(\d+\.\d+(?:\.\d+)?)/", re.I),
    # CDN estilo npm/unpkg/jsdelivr: /react@17.0.2/umd/react.js
    re.compile(r"/([a-zA-Z0-9_\-\.]+)@(\d+\.\d+(?:\.\d+)?)", re.I),
]

# Nombres genericos que no son librerias reales (evitar ruido).
IGNORAR_JS = {"app", "main", "index", "bundle", "script", "scripts", "style",
              "styles", "vendor", "common", "runtime", "chunk", "polyfills"}


def ejecutar(config: dict, logger: logging.Logger) -> list[Hallazgo]:
    """
    Punto de entrada del modulo (lo llama main.py).

    Combina Wappalyzer + analisis de cabeceras + meta generator para producir
    un inventario de tecnologias y detectar versiones expuestas.
    """
    objetivo = config["objetivo"]["url"].strip()
    opciones = config.get("opciones", {})
    timeout = opciones.get("timeout", 10)
    verificar_ssl = opciones.get("verificar_ssl", True)
    user_agent = opciones.get("user_agent", "AuditoriaWeb/1.0")

    logger.info(f"[tecnologias] Identificando tecnologias de {objetivo}")

    hallazgos: list[Hallazgo] = []

    # tecnologias detectadas: nombre -> conjunto de versiones (puede ir vacio)
    inventario: dict[str, set] = {}

    # --- Fuente 1: cabeceras HTTP (rapido y preciso para versiones) ---
    try:
        resp = requests.get(
            objetivo,
            timeout=timeout,
            verify=verificar_ssl,
            headers={"User-Agent": user_agent},
            allow_redirects=True,
        )
    except requests.exceptions.RequestException as e:
        logger.error(f"[tecnologias] No se pudo conectar con {objetivo}: {e}")
        return hallazgos

    hallazgos.extend(
        _analizar_cabeceras(resp, objetivo, inventario, logger)
    )

    # --- Fuente 2: meta generator en el HTML ---
    _analizar_meta_generator(resp.text, inventario, logger)

    # --- Fuente 3: versiones de librerias JS/CSS en el HTML ---
    _analizar_librerias_js(resp.text, inventario, logger)

    # --- Fuente 4: Wappalyzer (inventario amplio) ---
    _analizar_wappalyzer(objetivo, inventario, logger)

    # --- Hallazgo informativo con el inventario completo ---
    if inventario:
        lineas = []
        for tech in sorted(inventario):
            versiones = inventario[tech]
            if versiones:
                lineas.append(f"{tech} {', '.join(sorted(versiones))}")
            else:
                lineas.append(tech)
        resumen = "; ".join(lineas)

        hallazgos.append(Hallazgo(
            titulo="Inventario de tecnologias detectadas",
            categoria="A06",
            severidad="informativa",
            descripcion=(
                "Se identificaron las siguientes tecnologias en el objetivo. "
                "Este inventario es la base para verificar si alguna version "
                "tiene vulnerabilidades conocidas (CVE)."
            ),
            cvss=None,
            evidencia=resumen,
            recomendacion=(
                "Mantener todos los componentes actualizados y revisar sus "
                "versiones frente a bases de datos de vulnerabilidades."
            ),
            herramienta_origen=ORIGEN,
            url_afectada=objetivo,
        ))
        logger.info(f"[tecnologias] Inventario: {resumen}")

    logger.info(
        f"[tecnologias] Analisis terminado. {len(hallazgos)} hallazgo(s)."
    )
    return hallazgos


def _limpiar_version(version: str) -> str | None:
    """
    Limpia una cadena de version dejando solo el numero (ej: '2.4.41').
    Devuelve None si no hay un numero de version reconocible.
    """
    if not version:
        return None
    # Extraer el primer patron tipo X.Y o X.Y.Z del texto.
    m = re.search(r"\d+(?:\.\d+)+", version)
    return m.group(0) if m else None


def _agregar(inventario: dict, nombre: str, version: str | None = None) -> None:
    """Añade una tecnologia (y opcionalmente su version) al inventario."""
    # Limpiar el nombre de parentesis y comas sueltas.
    nombre = nombre.strip().strip("(),").strip()
    if not nombre or len(nombre) < 2:
        return
    if nombre not in inventario:
        inventario[nombre] = set()
    if version:
        ver_limpia = _limpiar_version(version)
        if ver_limpia:
            inventario[nombre].add(ver_limpia)


def _analizar_cabeceras(resp, objetivo, inventario, logger) -> list[Hallazgo]:
    """
    Extrae tecnologias y versiones de las cabeceras Server y X-Powered-By.
    Genera un hallazgo por cada version expuesta (A06: baja severidad).
    """
    hallazgos: list[Hallazgo] = []
    headers = resp.headers

    # Cabeceras que suelen revelar software y version.
    cabeceras_reveladoras = {
        "Server": "Servidor web",
        "X-Powered-By": "Framework/lenguaje",
        "X-AspNet-Version": "ASP.NET",
        "X-AspNetMvc-Version": "ASP.NET MVC",
    }

    for cabecera, descripcion in cabeceras_reveladoras.items():
        if cabecera not in headers:
            continue
        valor = headers[cabecera].strip()
        if not valor:
            continue

        # ¿El valor incluye una version? (ej: "Apache/2.4.41", "PHP/8.1.2")
        tiene_version = bool(re.search(r"\d+\.\d+", valor))

        # Registrar en el inventario, separando nombre/version si trae "/".
        for parte in valor.split():
            if "/" in parte:
                nombre, _, ver = parte.partition("/")
                _agregar(inventario, nombre, ver)
            else:
                _agregar(inventario, parte)

        # Si expone una version concreta, es un hallazgo A06.
        if tiene_version:
            hallazgos.append(Hallazgo(
                titulo=f"Version de software expuesta en cabecera {cabecera}",
                categoria="A06",
                severidad="baja",
                descripcion=(
                    f"La cabecera HTTP '{cabecera}' revela la version del "
                    f"software utilizado ({descripcion}). Exponer versiones "
                    f"facilita a un atacante buscar exploits especificos para "
                    f"esa version."
                ),
                cvss=3.1,
                evidencia=f"{cabecera}: {valor}",
                recomendacion=(
                    f"Configurar el servidor para no revelar la version en la "
                    f"cabecera '{cabecera}' (por ejemplo, 'ServerTokens Prod' "
                    f"en Apache o ocultar X-Powered-By)."
                ),
                herramienta_origen=ORIGEN,
                url_afectada=objetivo,
            ))
            logger.info(f"[tecnologias] Version expuesta: {cabecera}: {valor}")

    return hallazgos


def _analizar_meta_generator(html: str, inventario: dict, logger) -> None:
    """Busca la etiqueta <meta name='generator'> que revela CMS y version."""
    # Ejemplo: <meta name="generator" content="WordPress 6.4.2" />
    patron = re.compile(
        r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']',
        re.IGNORECASE,
    )
    m = patron.search(html)
    if not m:
        return
    contenido = m.group(1).strip()
    logger.info(f"[tecnologias] Meta generator: {contenido}")

    # Separar nombre y version (ej: "WordPress 6.4.2").
    m2 = re.match(r"(.+?)\s+([\d.]+)", contenido)
    if m2:
        _agregar(inventario, m2.group(1), m2.group(2))
    else:
        _agregar(inventario, contenido)


def _analizar_librerias_js(html: str, inventario: dict, logger) -> None:
    """
    Extrae librerias JS/CSS y sus versiones de los src/href del HTML.
    Los nombres de archivo y las URLs de CDN suelen incluir la version
    exacta, que es informacion muy valiosa para A06.
    """
    # Recoger todas las rutas de scripts y hojas de estilo.
    recursos = re.findall(r'(?:src|href)=["\']([^"\']+)["\']', html, re.IGNORECASE)

    detectadas = 0
    for recurso in recursos:
        for patron in PATRONES_JS:
            m = patron.search(recurso)
            if not m:
                continue
            libreria = m.group(1).lower().strip("/.-")
            version = m.group(2)

            # Descartar nombres genericos que no son librerias reales.
            if libreria in IGNORAR_JS or len(libreria) < 2:
                break

            _agregar(inventario, libreria, version)
            detectadas += 1
            logger.debug(f"[tecnologias] Libreria JS: {libreria} {version}")
            break  # ya casamos este recurso, pasar al siguiente

    if detectadas:
        logger.info(
            f"[tecnologias] {detectadas} libreria(s) JS/CSS con version "
            f"detectada(s) en el HTML."
        )


def _analizar_wappalyzer(objetivo, inventario, logger) -> None:
    """
    Usa Wappalyzer para un inventario amplio. Es opcional: si la libreria no
    esta instalada o falla, el modulo sigue con lo detectado por otras fuentes.
    """
    try:
        # Wappalyzer emite muchos warnings irrelevantes; los silenciamos.
        warnings.filterwarnings("ignore")
        from Wappalyzer import Wappalyzer, WebPage
    except Exception as e:
        # Capturamos CUALQUIER error de import, no solo ImportError. La libreria
        # python-Wappalyzer esta desactualizada y en versiones recientes de
        # Python (3.12+) su import puede fallar con otros tipos de error.
        logger.info(
            f"[tecnologias] Wappalyzer no esta disponible ({type(e).__name__}: "
            f"{e}). Se usa la deteccion por cabeceras y meta, que es la mas "
            f"fiable para versiones. El inventario sera algo mas limitado."
        )
        return

    try:
        wappalyzer = Wappalyzer.latest()
        page = WebPage.new_from_url(objetivo)
        resultado = wappalyzer.analyze_with_versions_and_categories(page)

        for nombre, info in resultado.items():
            versiones = info.get("versions", [])
            if versiones:
                for v in versiones:
                    _agregar(inventario, nombre, str(v))
            else:
                _agregar(inventario, nombre)
        logger.info(
            f"[tecnologias] Wappalyzer detecto {len(resultado)} tecnologia(s)."
        )
    except Exception as e:
        # Wappalyzer puede fallar por muchas razones (red, parsing...).
        # No es critico: seguimos con lo que ya tenemos.
        logger.warning(
            f"[tecnologias] Wappalyzer no pudo completar el analisis: {e}. "
            f"Se continua con la deteccion por cabeceras y meta."
        )


# Prueba independiente:
#     python3 -m modulos.tecnologias
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    log = logging.getLogger("prueba")

    config_prueba = {
        "objetivo": {"url": "https://server.vulnapp.id/dvwa"},
        "opciones": {"timeout": 15, "verificar_ssl": True},
    }

    print("Probando el modulo tecnologias...\n")
    resultados = ejecutar(config_prueba, log)

    print(f"\nSe generaron {len(resultados)} hallazgos:\n")
    for h in resultados:
        print(h)
        print()