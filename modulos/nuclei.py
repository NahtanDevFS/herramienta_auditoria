"""
nuclei.py  (modulo de deteccion - A06/A10 y otros)
Envuelve la herramienta externa Nuclei (https://github.com/projectdiscovery/nuclei),
un escaner basado en miles de plantillas que detecta vulnerabilidades conocidas
(CVE), malas configuraciones, exposiciones y tecnologias.

Este modulo ESTRENA el patron "envolver un binario externo", que reutilizaremos
para nmap, sqlmap y ZAP. Los pasos del patron son:

  1. Comprobar que el binario existe en el sistema.
  2. Construir el comando con las opciones adecuadas.
  3. Ejecutarlo con subprocess, con un limite de tiempo (timeout).
  4. Parsear su salida (aqui, JSON linea a linea con -jsonl).
  5. Mapear cada resultado a nuestro objeto Hallazgo.
  6. Manejar todos los errores posibles sin romper la auditoria.

Nuclei puede tardar mucho (miles de plantillas), asi que por defecto:
  - Solo escanea severidades medium, high y critical (se salta info/low).
  - Aplica un timeout configurable.
  Ambos ajustes se pueden cambiar desde config.yaml.

Patron de siempre:
    def ejecutar(config, logger) -> list[Hallazgo]
"""

import json
import logging
import shutil
import subprocess

from core.modelo_hallazgo import Hallazgo, Severidad


ORIGEN = "modulo_nuclei"

# Nombre del binario. Debe estar en el PATH (o en ~/go/bin con el PATH ajustado).
BINARIO = "nuclei"

# Longitud maxima de la descripcion. Algunas plantillas de Nuclei (sobre todo
# las de CVE) traen descripciones enormes que listan decenas de productos
# afectados, lo que arruinaria la legibilidad del reporte final.
MAX_DESCRIPCION = 400

# Severidades que escaneamos por defecto (las relevantes para un informe).
SEVERIDADES_DEFECTO = "medium,high,critical"

# Timeout por defecto en segundos para todo el escaneo de Nuclei.
TIMEOUT_DEFECTO = 300  # 5 minutos

# Mapeo de la severidad de Nuclei a nuestra escala.
MAPA_SEVERIDAD = {
    "critical": Severidad.CRITICA,
    "high": Severidad.ALTA,
    "medium": Severidad.MEDIA,
    "low": Severidad.BAJA,
    "info": Severidad.INFORMATIVA,
    "unknown": Severidad.INFORMATIVA,
}

# Mapeo aproximado del tipo de plantilla a categoria OWASP.
# La mayoria de hallazgos de Nuclei encajan en A06 (componentes vulnerables)
# o A05 (malas configuraciones). Afinamos por tags cuando es posible.
def _categoria_desde_tags(tags: list[str], tiene_cve: bool) -> str:
    """Decide la categoria OWASP mas adecuada segun los tags de la plantilla."""
    tags_lower = {t.lower() for t in tags}

    if tags_lower & {"sqli", "xss", "rce", "injection", "lfi", "ssti", "cmdi"}:
        return "A03"  # Injection
    if tags_lower & {"ssrf"}:
        return "A10"  # SSRF
    if tags_lower & {"misconfig", "exposure", "config", "default-login"}:
        return "A05"  # Security Misconfiguration
    if tags_lower & {"auth", "default-login", "weak-auth"}:
        return "A07"  # Auth failures
    if tiene_cve or (tags_lower & {"cve", "tech", "wordpress", "wp-plugin"}):
        return "A06"  # Vulnerable components
    # Por defecto, lo tratamos como mala configuracion.
    return "A05"


def _localizar_binario(logger) -> str | None:
    """
    Busca el binario de nuclei. Primero en el PATH; si no esta, en las
    ubicaciones tipicas de instalacion (como ~/go/bin, donde 'go install' lo
    coloca). Devuelve la ruta al binario o None si no se encuentra.

    Esto hace el modulo robusto ante un PATH mal configurado, algo comun
    cuando se ejecuta desde un entorno virtual que no hereda ~/go/bin.
    """
    # 1. Buscar en el PATH normal.
    ruta = shutil.which(BINARIO)
    if ruta:
        return ruta

    # 2. Buscar en ubicaciones habituales.
    import os
    candidatos = [
        os.path.expanduser("~/go/bin/nuclei"),
        "/usr/local/bin/nuclei",
        "/usr/bin/nuclei",
        os.path.expanduser("~/.local/bin/nuclei"),
    ]
    for candidato in candidatos:
        if os.path.isfile(candidato) and os.access(candidato, os.X_OK):
            logger.info(f"[nuclei] Binario encontrado en {candidato}")
            return candidato

    return None


def ejecutar(config: dict, logger: logging.Logger) -> list[Hallazgo]:
    """
    Punto de entrada del modulo (lo llama main.py).

    Ejecuta Nuclei contra el objetivo y convierte cada deteccion en un Hallazgo.
    """
    objetivo = config["objetivo"]["url"].strip()
    opciones = config.get("opciones", {})

    # Opciones especificas de Nuclei desde config.yaml (seccion 'nuclei').
    conf_nuclei = config.get("nuclei", {})
    severidades = conf_nuclei.get("severidades", SEVERIDADES_DEFECTO)
    timeout = conf_nuclei.get("timeout", TIMEOUT_DEFECTO)

    logger.info(f"[nuclei] Preparando escaneo de {objetivo}")

    hallazgos: list[Hallazgo] = []

    # --- Paso 1: comprobar que Nuclei esta instalado ---
    ruta_binario = _localizar_binario(logger)
    if ruta_binario is None:
        logger.error(
            "[nuclei] No se encontro el binario 'nuclei' ni en el PATH ni en "
            "las ubicaciones habituales (~/go/bin, /usr/local/bin...). "
            "Instalalo y asegurate de que este accesible. Se omite este modulo."
        )
        return hallazgos

    # --- Paso 2: construir el comando ---
    comando = [
        ruta_binario,
        "-u", objetivo,
        "-jsonl",              # salida JSON, una deteccion por linea
        "-silent",             # sin banner ni ruido en stdout
        "-severity", severidades,
        "-no-color",
        "-disable-update-check",
    ]

    logger.info(
        f"[nuclei] Ejecutando escaneo (severidades: {severidades}, "
        f"timeout: {timeout}s). Esto puede tardar varios minutos..."
    )
    logger.debug(f"[nuclei] Comando: {' '.join(comando)}")

    # --- Paso 3: ejecutar con subprocess y timeout ---
    try:
        proceso = subprocess.run(
            comando,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        logger.warning(
            f"[nuclei] El escaneo supero el timeout de {timeout}s y se detuvo. "
            f"Se procesan los resultados obtenidos hasta ahora (si los hay)."
        )
        # En caso de timeout no tenemos stdout; devolvemos lo que haya (nada).
        return hallazgos
    except Exception as e:
        logger.error(f"[nuclei] Error al ejecutar Nuclei: {e}")
        return hallazgos

    # --- Paso 4 y 5: parsear la salida JSONL y mapear a Hallazgo ---
    salida = proceso.stdout or ""
    lineas = [l for l in salida.splitlines() if l.strip()]

    if not lineas:
        logger.info(
            "[nuclei] El escaneo termino sin detecciones en las severidades "
            "seleccionadas."
        )
        return hallazgos

    for linea in lineas:
        hallazgo = _parsear_linea(linea, objetivo, logger)
        if hallazgo:
            hallazgos.append(hallazgo)

    logger.info(
        f"[nuclei] Escaneo terminado. {len(hallazgos)} deteccion(es) "
        f"convertida(s) en hallazgos."
    )
    return hallazgos


def _parsear_linea(linea: str, objetivo: str, logger) -> Hallazgo | None:
    """
    Convierte una linea JSON de Nuclei en un objeto Hallazgo.
    Devuelve None si la linea no se puede parsear.
    """
    try:
        datos = json.loads(linea)
    except json.JSONDecodeError:
        logger.debug(f"[nuclei] Linea no es JSON valido, se ignora: {linea[:80]}")
        return None

    info = datos.get("info", {})
    nombre = info.get("name", datos.get("template-id", "Deteccion de Nuclei"))
    severidad_txt = info.get("severity", "info").lower()
    severidad = MAPA_SEVERIDAD.get(severidad_txt, Severidad.INFORMATIVA)
    descripcion = info.get("description", "").strip() or (
        "Deteccion realizada por la plantilla de Nuclei "
        f"'{datos.get('template-id', 'desconocida')}'."
    )
    # Truncar descripciones desmesuradas (habitual en plantillas de CVE) para
    # que el reporte final sea legible. Se corta en el ultimo punto antes del
    # limite, para no partir una frase por la mitad.
    if len(descripcion) > MAX_DESCRIPCION:
        recorte = descripcion[:MAX_DESCRIPCION]
        ultimo_punto = recorte.rfind(". ")
        if ultimo_punto > 100:
            descripcion = recorte[:ultimo_punto + 1] + " [...]"
        else:
            descripcion = recorte.rstrip() + " [...]"
    tags = info.get("tags", []) or []

    # Clasificacion: CVSS y CVE si la plantilla los aporta.
    clasificacion = info.get("classification") or {}
    cvss = clasificacion.get("cvss-score")
    cve_ids = clasificacion.get("cve-id") or []
    tiene_cve = bool(cve_ids)

    # Normalizar CVSS a float valido en rango, o None.
    if cvss is not None:
        try:
            cvss = float(cvss)
            if not (0.0 <= cvss <= 10.0):
                cvss = None
        except (ValueError, TypeError):
            cvss = None

    categoria = _categoria_desde_tags(tags, tiene_cve)

    # Construir la evidencia con los datos mas utiles de Nuclei.
    matched_at = datos.get("matched-at", objetivo)
    template_id = datos.get("template-id", "")
    extraidos = datos.get("extracted-results") or []

    partes_evidencia = [
        f"Plantilla: {template_id}",
        f"Coincidencia en: {matched_at}",
    ]
    if cve_ids:
        partes_evidencia.append(f"CVE: {', '.join(cve_ids)}")
    if extraidos:
        # Limitar para no llenar el reporte.
        muestra = ", ".join(str(e) for e in extraidos[:5])
        partes_evidencia.append(f"Datos extraidos: {muestra}")
    evidencia = " | ".join(partes_evidencia)

    # Referencias como recomendacion base.
    referencias = info.get("reference") or []
    if referencias:
        recomendacion = (
            "Revisar y remediar segun las referencias de la plantilla: "
            + "; ".join(referencias[:3])
        )
    else:
        recomendacion = (
            "Revisar la deteccion y aplicar la correccion correspondiente "
            "(actualizar el componente, corregir la configuracion o mitigar la "
            "vulnerabilidad)."
        )

    # El titulo incluye el CVE si existe, util para el informe.
    titulo = nombre
    if cve_ids:
        titulo = f"{nombre} ({', '.join(cve_ids)})"

    return Hallazgo(
        titulo=titulo,
        categoria=categoria,
        severidad=severidad,
        descripcion=descripcion,
        cvss=cvss,
        evidencia=evidencia,
        recomendacion=recomendacion,
        herramienta_origen=ORIGEN,
        url_afectada=matched_at,
    )


# Prueba independiente:
#     python3 -m modulos.nuclei
# Requiere tener nuclei instalado. Escanea un objetivo publico de prueba.
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    log = logging.getLogger("prueba")

    config_prueba = {
        "objetivo": {"url": "http://scanme.nmap.org"},
        "opciones": {},
        # Para la prueba, bajamos el timeout y ampliamos severidades para que
        # salga algo (scanme suele dar detecciones low/info).
        "nuclei": {"severidades": "low,medium,high,critical", "timeout": 180},
    }

    print("Probando el modulo nuclei contra scanme.nmap.org ...")
    print("(Esto puede tardar 1-3 minutos)\n")
    resultados = ejecutar(config_prueba, log)

    print(f"\nSe generaron {len(resultados)} hallazgos:\n")
    for h in resultados:
        print(h)
        print()