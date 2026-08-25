"""
nmap.py  (modulo de deteccion - A05: Security Misconfiguration)
Escanea los puertos abiertos del objetivo e identifica los servicios que corren
en ellos. Un puerto innecesariamente expuesto amplia la superficie de ataque,
por eso encaja en A05 (mala configuracion).

Que detecta:
  - Puertos abiertos y el servicio/version que corre en cada uno.
  - Servicios de riesgo expuestos a internet (bases de datos, escritorio
    remoto, FTP, etc.) que normalmente NO deberian ser publicos.
  - Servicios con protocolos inseguros (telnet, ftp sin cifrar).

Decisiones de diseño importantes:

  1. NO requiere sudo. El escaneo SYN (-sS) y la deteccion de SO necesitan
     privilegios de root; usamos -sT (TCP connect), que funciona como usuario
     normal. Es algo mas lento pero evita pedir sudo, lo que hace la
     herramienta mas segura y portable.

  2. Alcance acotado. Escanear los 65535 puertos tarda demasiado. Por defecto
     usamos los 1000 puertos mas comunes (--top-ports 1000), configurable
     desde config.yaml.

  3. Usamos subprocess + salida XML en vez de la libreria python-nmap, que es
     un wrapper que añade dependencias y a veces falla. Parsear el XML nativo
     de nmap es mas fiable.

Patron de siempre:
    def ejecutar(config, logger) -> list[Hallazgo]
"""

import logging
import os
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

from core.modelo_hallazgo import Hallazgo


ORIGEN = "modulo_nmap"

BINARIO = "nmap"

# Puertos a escanear por defecto (los N mas comunes segun nmap).
TOP_PORTS_DEFECTO = 1000

# Timeout por defecto del escaneo completo, en segundos.
TIMEOUT_DEFECTO = 300

# Puertos que en un servidor web publico casi nunca deberian estar expuestos.
# Cada entrada: puerto -> (nombre del servicio, severidad, cvss, motivo)
SERVICIOS_RIESGO = {
    21:    ("FTP", "media", 5.3,
            "FTP transmite credenciales y datos sin cifrar."),
    23:    ("Telnet", "alta", 7.5,
            "Telnet transmite todo, incluidas las credenciales, en texto claro."),
    135:   ("MSRPC", "media", 5.3,
            "Servicio RPC de Windows expuesto; no deberia ser accesible desde "
            "internet."),
    139:   ("NetBIOS", "media", 5.3,
            "NetBIOS expuesto puede filtrar informacion de la red interna."),
    445:   ("SMB", "alta", 7.5,
            "SMB expuesto a internet es un vector de ataque habitual "
            "(ransomware, ejecucion remota)."),
    1433:  ("MSSQL", "alta", 7.5,
            "Base de datos SQL Server accesible; deberia estar restringida a "
            "la red interna."),
    3306:  ("MySQL", "alta", 7.5,
            "Base de datos MySQL accesible; deberia estar restringida a la red "
            "interna."),
    3389:  ("RDP", "alta", 7.5,
            "Escritorio remoto expuesto; objetivo frecuente de ataques de "
            "fuerza bruta."),
    5432:  ("PostgreSQL", "alta", 7.5,
            "Base de datos PostgreSQL accesible; deberia estar restringida a "
            "la red interna."),
    5900:  ("VNC", "alta", 7.5,
            "VNC expuesto permite control remoto; a menudo con autenticacion "
            "debil."),
    6379:  ("Redis", "critica", 9.1,
            "Redis suele venir sin autenticacion por defecto; expuesto permite "
            "leer y escribir datos, e incluso ejecutar comandos."),
    27017: ("MongoDB", "critica", 9.1,
            "MongoDB expuesto sin autenticacion permite acceso completo a la "
            "base de datos."),
    9200:  ("Elasticsearch", "alta", 7.5,
            "Elasticsearch expuesto suele permitir consultar y modificar todos "
            "los indices sin autenticacion."),
    11211: ("Memcached", "alta", 7.5,
            "Memcached expuesto permite leer datos cacheados y puede usarse "
            "para amplificacion de DDoS."),
}


def _localizar_binario(logger) -> str | None:
    """
    Busca el binario de nmap: primero en el PATH, luego en ubicaciones
    habituales. Mismo patron que usamos en el modulo de Nuclei, para no
    depender de que el PATH este bien configurado.
    """
    ruta = shutil.which(BINARIO)
    if ruta:
        return ruta

    candidatos = [
        "/usr/bin/nmap",
        "/usr/local/bin/nmap",
        "/opt/homebrew/bin/nmap",
    ]
    for candidato in candidatos:
        if os.path.isfile(candidato) and os.access(candidato, os.X_OK):
            logger.info(f"[nmap] Binario encontrado en {candidato}")
            return candidato

    return None


def ejecutar(config: dict, logger: logging.Logger) -> list[Hallazgo]:
    """
    Punto de entrada del modulo (lo llama main.py).

    Escanea los puertos del host objetivo y genera:
      - Un hallazgo informativo con el inventario de puertos/servicios abiertos.
      - Un hallazgo por cada servicio de riesgo expuesto.
    """
    objetivo_url = config["objetivo"]["url"].strip()
    host = urlparse(objetivo_url).hostname

    if not host:
        logger.error(f"[nmap] No se pudo extraer el host de: {objetivo_url}")
        return []

    conf_nmap = config.get("nmap", {})
    top_ports = conf_nmap.get("top_ports", TOP_PORTS_DEFECTO)
    timeout = conf_nmap.get("timeout", TIMEOUT_DEFECTO)
    puertos_especificos = conf_nmap.get("puertos")  # ej: "80,443,8080"

    hallazgos: list[Hallazgo] = []

    # --- Paso 1: localizar el binario ---
    ruta_binario = _localizar_binario(logger)
    if ruta_binario is None:
        logger.error(
            "[nmap] No se encontro el binario 'nmap'. Instalalo con: "
            "sudo apt install nmap. Se omite este modulo."
        )
        return hallazgos

    # --- Paso 2: construir el comando ---
    # Archivo temporal para la salida XML.
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
        ruta_xml = tmp.name

    comando = [
        ruta_binario,
        "-sT",           # TCP connect: no requiere sudo
        "-Pn",           # no hacer ping previo (muchos hosts lo bloquean)
        "-sV",           # detectar version del servicio
        "--open",        # mostrar solo puertos abiertos
        "-oX", ruta_xml, # salida en XML
    ]

    if puertos_especificos:
        comando.extend(["-p", str(puertos_especificos)])
        alcance = f"puertos {puertos_especificos}"
    else:
        comando.extend(["--top-ports", str(top_ports)])
        alcance = f"top {top_ports} puertos"

    comando.append(host)

    logger.info(
        f"[nmap] Escaneando {host} ({alcance}, timeout {timeout}s). "
        f"Esto puede tardar varios minutos..."
    )
    logger.info(
        "[nmap] Nota: se usa escaneo TCP connect (-sT) para no requerir sudo. "
        "La deteccion de SO y el escaneo SYN no estan disponibles sin root."
    )
    logger.debug(f"[nmap] Comando: {' '.join(comando)}")

    # --- Paso 3: ejecutar ---
    try:
        subprocess.run(
            comando,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        logger.warning(
            f"[nmap] El escaneo supero el timeout de {timeout}s. "
            f"Considera reducir 'top_ports' en config.yaml. "
            f"Se intentan procesar los resultados parciales."
        )
    except Exception as e:
        logger.error(f"[nmap] Error al ejecutar nmap: {e}")
        _borrar(ruta_xml)
        return hallazgos

    # Paso 4: parsear el XML 
    try:
        puertos = _parsear_xml(ruta_xml, logger)
    except Exception as e:
        logger.error(f"[nmap] Error al parsear la salida de nmap: {e}")
        _borrar(ruta_xml)
        return hallazgos
    finally:
        _borrar(ruta_xml)

    if not puertos:
        logger.info("[nmap] No se encontraron puertos abiertos.")
        return hallazgos

    logger.info(f"[nmap] {len(puertos)} puerto(s) abierto(s) encontrado(s).")

    # Paso 5: generar hallazgos 
    # 5a. Inventario informativo de todos los puertos abiertos.
    lineas = []
    for p in puertos:
        desc = f"{p['puerto']}/{p['protocolo']} {p['servicio']}"
        if p["producto"]:
            desc += f" ({p['producto']}"
            if p["version"]:
                desc += f" {p['version']}"
            desc += ")"
        lineas.append(desc)
        # Mostrar cada puerto en el log: para nmap, esta es la informacion
        # principal y conviene verla durante la ejecucion.
        logger.info(f"[nmap]   -> {desc}")

    hallazgos.append(Hallazgo(
        titulo=f"Puertos abiertos detectados ({len(puertos)})",
        categoria="A05",
        severidad="informativa",
        descripcion=(
            "Inventario de los puertos abiertos y los servicios detectados en "
            "el objetivo. Cada puerto expuesto amplia la superficie de ataque; "
            "conviene cerrar los que no sean estrictamente necesarios."
        ),
        cvss=None,
        evidencia="; ".join(lineas),
        recomendacion=(
            "Revisar cada puerto y cerrar o restringir por firewall los que no "
            "sean necesarios para el servicio publico."
        ),
        herramienta_origen=ORIGEN,
        url_afectada=host,
    ))

    # 5b. Un hallazgo por cada servicio de riesgo expuesto.
    for p in puertos:
        num = p["puerto"]
        if num not in SERVICIOS_RIESGO:
            continue

        nombre, severidad, cvss, motivo = SERVICIOS_RIESGO[num]

        detalle_version = ""
        if p["producto"]:
            detalle_version = f" Servicio detectado: {p['producto']}"
            if p["version"]:
                detalle_version += f" {p['version']}"
            detalle_version += "."

        hallazgos.append(Hallazgo(
            titulo=f"Servicio de riesgo expuesto: {nombre} (puerto {num})",
            categoria="A05",
            severidad=severidad,
            descripcion=(
                f"El puerto {num} ({nombre}) esta abierto y accesible. {motivo}"
                f"{detalle_version}"
            ),
            cvss=cvss,
            evidencia=(
                f"{host}:{num} abierto - servicio: {p['servicio']}"
                + (f" {p['producto']} {p['version']}".rstrip()
                   if p["producto"] else "")
            ),
            recomendacion=(
                f"Restringir el acceso al puerto {num} mediante firewall, "
                f"permitiendolo solo desde las IPs que lo necesiten, o cerrarlo "
                f"si el servicio no debe ser accesible desde el exterior."
            ),
            herramienta_origen=ORIGEN,
            url_afectada=f"{host}:{num}",
        ))
        logger.info(f"[nmap] Servicio de riesgo expuesto: {nombre} ({num})")

    logger.info(f"[nmap] Analisis terminado. {len(hallazgos)} hallazgo(s).")
    return hallazgos


def _parsear_xml(ruta_xml: str, logger) -> list[dict]:
    """
    Lee el XML generado por nmap y devuelve la lista de puertos abiertos.
    Cada elemento: {puerto, protocolo, servicio, producto, version}
    """
    if not os.path.isfile(ruta_xml) or os.path.getsize(ruta_xml) == 0:
        logger.warning("[nmap] El archivo de salida XML esta vacio o no existe.")
        return []

    arbol = ET.parse(ruta_xml)
    raiz = arbol.getroot()

    puertos = []
    # Estructura: <nmaprun><host><ports><port portid="80" protocol="tcp">
    #               <state state="open"/>
    #               <service name="http" product="nginx" version="1.18"/>
    for host_el in raiz.findall("host"):
        ports_el = host_el.find("ports")
        if ports_el is None:
            continue

        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            servicio_el = port_el.find("service")
            puertos.append({
                "puerto": int(port_el.get("portid", 0)),
                "protocolo": port_el.get("protocol", "tcp"),
                "servicio": (servicio_el.get("name", "desconocido")
                             if servicio_el is not None else "desconocido"),
                "producto": (servicio_el.get("product", "")
                             if servicio_el is not None else ""),
                "version": (servicio_el.get("version", "")
                            if servicio_el is not None else ""),
            })

    return puertos


def _borrar(ruta: str) -> None:
    """Elimina el archivo temporal, ignorando errores."""
    try:
        os.unlink(ruta)
    except OSError:
        pass


# Prueba independiente:
#     python3 -m modulos.nmap
# Escanea scanme.nmap.org, que autoriza explicitamente ser escaneado.
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    log = logging.getLogger("prueba")

    config_prueba = {
        "objetivo": {"url": "http://scanme.nmap.org"},
        "opciones": {},
        # Para la prueba usamos pocos puertos para que sea rapido.
        "nmap": {"puertos": "22,80,443,3306", "timeout": 120},
    }

    print("Probando el modulo nmap contra scanme.nmap.org ...")
    print("(scanme.nmap.org autoriza explicitamente los escaneos)\n")
    resultados = ejecutar(config_prueba, log)

    print(f"\nSe generaron {len(resultados)} hallazgos:\n")
    for h in resultados:
        print(h)
        print(f"    Evidencia: {h.evidencia}")
        print()