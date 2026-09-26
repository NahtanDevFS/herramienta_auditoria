# identifica tecnologias y versiones mediante cabeceras, meta generator, js y wappalyzer

import logging
import re
import warnings

import requests

from core.modelo_hallazgo import Hallazgo


ORIGEN = "modulo_tecnologias"


# extrae versiones de js/css desde el nombre de archivo o url del cdn

PATRONES_JS = [
    # archivo local con version: /js/jquery 3 6 0 min js o angular 1 8 2 js
    re.compile(r"/([a-zA-Z0-9_\-\.]+?)[-\.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.(?:js|css)", re.I),
    # cdn estilo cdnjs: /ajax/libs/bootstrap/5 1 3/js/bootstrap min js
    re.compile(r"/libs?/([a-zA-Z0-9_\-\.]+)/(\d+\.\d+(?:\.\d+)?)/", re.I),
    # cdn estilo npm/unpkg/jsdelivr: /react@17 0 2/umd/react js
    re.compile(r"/([a-zA-Z0-9_\-\.]+)@(\d+\.\d+(?:\.\d+)?)", re.I),
]

# nombres genericos que no son librerias reales (evitar ruido)
IGNORAR_JS = {"app", "main", "index", "bundle", "script", "scripts", "style",
              "styles", "vendor", "common", "runtime", "chunk", "polyfills"}


def ejecutar(config: dict, logger: logging.Logger) -> list[Hallazgo]:
    # punto de entrada combina wappalyzer, cabeceras y meta generator para el inventario
    objetivo = config["objetivo"]["url"].strip()
    opciones = config.get("opciones", {})
    timeout = opciones.get("timeout", 10)
    verificar_ssl = opciones.get("verificar_ssl", True)
    user_agent = opciones.get("user_agent", "AuditoriaWeb/1.0")

    logger.info(f"[tecnologias] Identificando tecnologias de {objetivo}")

    hallazgos: list[Hallazgo] = []

    # tecnologias detectadas: nombre > conjunto de versiones (puede ir vacio)
    inventario: dict[str, set] = {}

    # fuente 1: cabeceras HTTP (rapido y preciso para versiones)
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

    # fuente 2: meta generator en el HTML
    _analizar_meta_generator(resp.text, inventario, logger)

    # fuente 3: versiones de librerias js/css en el HTML
    _analizar_librerias_js(resp.text, inventario, logger)

    # fuente 4: wappalyzer (inventario amplio)
    _analizar_wappalyzer(objetivo, inventario, logger)

    # hallazgo informativo con el inventario completo
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
            categoria="A03",
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
    # limpia una cadena de version dejando solo el numero (ej: '2 4 41')
    if not version:
        return None
    # extraer el primer patron tipo x y o x y z del texto
    m = re.search(r"\d+(?:\.\d+)+", version)
    return m.group(0) if m else None


def _agregar(inventario: dict, nombre: str, version: str | None = None) -> None:
    # añade una tecnologia (y opcionalmente su version) al inventario
    # limpiar el nombre de parentesis y comas sueltas
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
    # extrae tecnologias y versiones de las cabeceras server y x powered by
    hallazgos: list[Hallazgo] = []
    headers = resp.headers

    # cabeceras que suelen revelar software y version
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

        # ¿el valor incluye una version? (ej: "apache/2 4 41", "php/8 1 2")
        tiene_version = bool(re.search(r"\d+\.\d+", valor))

        # registrar en el inventario, separando nombre/version si trae "/"
        for parte in valor.split():
            if "/" in parte:
                nombre, _, ver = parte.partition("/")
                _agregar(inventario, nombre, ver)
            else:
                _agregar(inventario, parte)

        # si expone una version concreta, es un hallazgo a06
        if tiene_version:
            hallazgos.append(Hallazgo(
                titulo=f"Version de software expuesta en cabecera {cabecera}",
                categoria="A03",
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
    # busca la etiqueta <meta name='generator'> que revela cms y version
    # ejemplo: <meta name="generator" content="wordpress 6 4 2" />
    patron = re.compile(
        r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']',
        re.IGNORECASE,
    )
    m = patron.search(html)
    if not m:
        return
    contenido = m.group(1).strip()
    logger.info(f"[tecnologias] Meta generator: {contenido}")

    # separar nombre y version (ej: "wordpress 6 4 2")
    m2 = re.match(r"(.+?)\s+([\d.]+)", contenido)
    if m2:
        _agregar(inventario, m2.group(1), m2.group(2))
    else:
        _agregar(inventario, contenido)


def _analizar_librerias_js(html: str, inventario: dict, logger) -> None:
    # extrae librerias js/css y sus versiones de los src/href del HTML
    # recoger todas las rutas de scripts y hojas de estilo
    recursos = re.findall(r'(?:src|href)=["\']([^"\']+)["\']', html, re.IGNORECASE)

    detectadas = 0
    for recurso in recursos:
        for patron in PATRONES_JS:
            m = patron.search(recurso)
            if not m:
                continue
            libreria = m.group(1).lower().strip("/.-")
            version = m.group(2)

            # descartar nombres genericos que no son librerias reales
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
    # usa wappalyzer para un inventario amplio es opcional (falla suave)
    try:
        # wappalyzer emite muchos warnings irrelevantes los silenciamos
        warnings.filterwarnings("ignore")
        from Wappalyzer import Wappalyzer, WebPage
    except Exception as e:
        # ignora fallos de wappalyzer, ya que en python 3.12+ su import falla
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
        # wappalyzer puede fallar por muchas razones (red, parsing )
        # no es critico: seguimos con lo que ya tenemos
        logger.warning(
            f"[tecnologias] Wappalyzer no pudo completar el analisis: {e}. "
            f"Se continua con la deteccion por cabeceras y meta."
        )


# prueba independiente:
# python3 m modulos tecnologias
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