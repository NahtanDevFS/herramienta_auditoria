"""
sqlmap.py  (modulo de deteccion - A03: Injection)
Envuelve sqlmap para detectar vulnerabilidades de inyeccion SQL en URLs con
parametros. Es el modulo mas intrusivo del proyecto: sqlmap NO solo observa,
sino que ATACA activamente enviando payloads de inyeccion SQL reales.

Por eso, este modulo:
  - Solo se ejecuta contra objetivos autorizados (como el resto, pero aqui es
    especialmente importante).
  - Usa una configuracion CONSERVADORA por defecto (level=1, risk=1): detecta
    sin tecnicas agresivas que puedan dañar o alterar datos.
  - Requiere URLs CON PARAMETROS (ej: /producto?id=1). Sin parametros, sqlmap
    no tiene donde inyectar. Las URLs se definen en config.yaml (seccion
    'sqlmap: urls'). Mas adelante, el crawler (Fase 4) podra alimentarlas.

Que detecta:
  - Parametros vulnerables a inyeccion SQL.
  - El tipo de inyeccion (boolean-based, UNION, time-based, etc.).
  - El motor de base de datos (DBMS) detectado.

Patron de siempre:
    def ejecutar(config, logger) -> list[Hallazgo]
"""

import logging
import os
import re
import shutil
import subprocess

from core.modelo_hallazgo import Hallazgo


ORIGEN = "modulo_sqlmap"

BINARIO = "sqlmap"

# Timeout por defecto POR CADA URL probada, en segundos.
TIMEOUT_POR_URL = 180


def _localizar_binario(logger) -> str | None:
    """Busca sqlmap en el PATH y en ubicaciones habituales."""
    ruta = shutil.which(BINARIO)
    if ruta:
        return ruta
    candidatos = [
        "/usr/bin/sqlmap",
        "/usr/local/bin/sqlmap",
        os.path.expanduser("~/.local/bin/sqlmap"),
    ]
    for c in candidatos:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            logger.info(f"[sqlmap] Binario encontrado en {c}")
            return c
    return None


def ejecutar(config: dict, logger: logging.Logger) -> list[Hallazgo]:
    """
    Punto de entrada del modulo (lo llama main.py).

    Prueba cada URL con parametros definida en config y genera un Hallazgo
    critico por cada inyeccion SQL confirmada.
    """
    conf_sqlmap = config.get("sqlmap", {})
    urls = conf_sqlmap.get("urls", []) or []
    timeout = conf_sqlmap.get("timeout", TIMEOUT_POR_URL)
    nivel = conf_sqlmap.get("level", 1)
    riesgo = conf_sqlmap.get("risk", 1)

    hallazgos: list[Hallazgo] = []

    # --- Comprobacion previa: hace falta al menos una URL con parametros ---
    if not urls:
        logger.warning(
            "[sqlmap] No hay URLs con parametros definidas en config.yaml "
            "(seccion 'sqlmap: urls'). sqlmap necesita URLs tipo "
            "'http://sitio/pagina?id=1' para poder inyectar. Se omite el modulo."
        )
        return hallazgos

    # --- Localizar el binario ---
    ruta_binario = _localizar_binario(logger)
    if ruta_binario is None:
        logger.error(
            "[sqlmap] No se encontro el binario 'sqlmap'. Instalalo con: "
            "sudo apt install sqlmap. Se omite este modulo."
        )
        return hallazgos

    opciones = config.get("opciones", {})
    user_agent = opciones.get("user_agent", "AuditoriaWeb/1.0")

    # --- Probar cada URL ---
    for url in urls:
        if "?" not in url or "=" not in url:
            logger.warning(
                f"[sqlmap] La URL '{url}' no tiene parametros (falta '?param='). "
                f"sqlmap no puede inyectar aqui. Se salta."
            )
            continue

        logger.info(f"[sqlmap] Probando inyeccion SQL en: {url}")
        hallazgo = _probar_url(
            ruta_binario, url, timeout, nivel, riesgo, user_agent, logger
        )
        if hallazgo:
            hallazgos.append(hallazgo)

    logger.info(
        f"[sqlmap] Analisis terminado. {len(hallazgos)} inyeccion(es) SQL "
        f"detectada(s)."
    )
    return hallazgos


def _probar_url(ruta_binario, url, timeout, nivel, riesgo, user_agent, logger):
    """
    Ejecuta sqlmap contra UNA url y devuelve un Hallazgo si encuentra
    inyeccion, o None si no.
    """
    comando = [
        ruta_binario,
        "-u", url,
        "--batch",               # no preguntar nada, usar respuestas por defecto
        f"--level={nivel}",      # profundidad de las pruebas (1 = conservador)
        f"--risk={riesgo}",      # riesgo de los payloads (1 = no altera datos)
        "--technique=BEUST",     # tecnicas: Boolean, Error, Union, Stacked, Time
        "--flush-session",       # no reutilizar resultados de sesiones previas
        "--disable-coloring",
        f"--user-agent={user_agent}",
    ]

    logger.debug(f"[sqlmap] Comando: {' '.join(comando)}")

    try:
        proceso = subprocess.run(
            comando,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        logger.warning(
            f"[sqlmap] La prueba de {url} supero el timeout de {timeout}s. "
            f"Se salta esta URL."
        )
        return None
    except Exception as e:
        logger.error(f"[sqlmap] Error al ejecutar sqlmap sobre {url}: {e}")
        return None

    salida = proceso.stdout or ""
    # Quitar posibles codigos de color ANSI residuales.
    salida = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", salida)

    return _parsear_salida(salida, url, logger)


def _parsear_salida(salida: str, url: str, logger):
    """
    Analiza la salida de sqlmap. Si detecto inyeccion, extrae el parametro,
    las tecnicas y el DBMS, y construye un Hallazgo critico.

    sqlmap indica exito con la frase 'is vulnerable' y lista los puntos de
    inyeccion en un bloque con 'Parameter:', 'Type:', 'Title:', 'Payload:'.
    """
    # ¿Encontro inyeccion? Buscamos las señales claras de sqlmap.
    vulnerable = (
        "is vulnerable" in salida
        or "identified the following injection point" in salida
        or "sqlmap identified" in salida
    )

    if not vulnerable:
        logger.info(f"[sqlmap] No se detecto inyeccion SQL en {url}.")
        return None

    # --- Extraer el parametro vulnerable ---
    m_param = re.search(r"Parameter:\s*(.+?)\s*\(", salida)
    parametro = m_param.group(1).strip() if m_param else "desconocido"

    # --- Extraer los tipos de inyeccion (puede haber varios) ---
    tipos = re.findall(r"Type:\s*(.+)", salida)
    tipos = [t.strip() for t in tipos]
    tipos_txt = ", ".join(dict.fromkeys(tipos)) if tipos else "no especificado"

    # --- Extraer el titulo de la primera tecnica (mas descriptivo) ---
    m_title = re.search(r"Title:\s*(.+)", salida)
    titulo_tecnica = m_title.group(1).strip() if m_title else ""

    # --- Extraer el DBMS detectado ---
    m_dbms = re.search(r"back-end DBMS:\s*(.+)", salida)
    if not m_dbms:
        m_dbms = re.search(r"the back-end DBMS is\s*(.+)", salida)
    dbms = m_dbms.group(1).strip() if m_dbms else "desconocido"

    # --- Extraer un payload de ejemplo (evidencia concreta) ---
    m_payload = re.search(r"Payload:\s*(.+)", salida)
    payload = m_payload.group(1).strip() if m_payload else ""

    logger.info(
        f"[sqlmap] INYECCION SQL detectada en '{parametro}' ({url}). "
        f"DBMS: {dbms}."
    )

    evidencia = (
        f"Parametro vulnerable: {parametro}. Tecnicas: {tipos_txt}. "
        f"DBMS: {dbms}."
    )
    if payload:
        evidencia += f" Payload de ejemplo: {payload[:150]}"

    descripcion = (
        f"El parametro '{parametro}' es vulnerable a inyeccion SQL. Un atacante "
        f"puede manipular las consultas a la base de datos ({dbms}) para leer, "
        f"modificar o eliminar datos, e incluso comprometer el servidor. Es una "
        f"de las vulnerabilidades mas criticas segun OWASP."
    )
    if titulo_tecnica:
        descripcion += f" Tecnica confirmada: {titulo_tecnica}."

    return Hallazgo(
        titulo=f"Inyeccion SQL en el parametro '{parametro}'",
        categoria="A03",
        severidad="critica",
        descripcion=descripcion,
        cvss=9.8,  # SQLi explotable es de las mas graves
        evidencia=evidencia,
        recomendacion=(
            "Usar consultas parametrizadas (prepared statements) en lugar de "
            "concatenar entradas del usuario en las consultas SQL. Validar y "
            "sanitizar toda entrada. Aplicar el principio de minimo privilegio "
            "en la cuenta de base de datos."
        ),
        herramienta_origen=ORIGEN,
        url_afectada=url,
    )


# Prueba independiente:
#     python3 -m modulos.sqlmap
# IMPORTANTE: apunta a un objetivo vulnerable AUTORIZADO. Aqui usamos un
# servidor local de prueba que debes tener corriendo (ver la conversacion).
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    log = logging.getLogger("prueba")

    config_prueba = {
        "opciones": {},
        "sqlmap": {
            "urls": ["http://127.0.0.1:8094/user?id=1"],
            "timeout": 150,
            "level": 1,
            "risk": 1,
        },
    }

    print("Probando el modulo sqlmap ...")
    print("(Requiere un servidor vulnerable AUTORIZADO en 127.0.0.1:8094)\n")
    resultados = ejecutar(config_prueba, log)

    print(f"\nSe generaron {len(resultados)} hallazgos:\n")
    for h in resultados:
        print(h)
        print(f"    Evidencia: {h.evidencia}")
        print()