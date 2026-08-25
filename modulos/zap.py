"""
zap.py  (modulo de deteccion - A03: Injection, y otros)
Integra OWASP ZAP, el escaner web de referencia de OWASP, para detectar
vulnerabilidades activas como XSS, inyecciones, y muchas otras.

ESTE MODULO ES DISTINTO A TODOS LOS ANTERIORES. ZAP no es un binario que se
ejecuta y termina: es un DAEMON (un proceso que se queda corriendo) al que se
le habla por una API HTTP. El ciclo de vida es:

  1. Lanzar ZAP en modo daemon (headless, sin interfaz grafica).
  2. Esperar a que arranque y responda por su API (tarda 20-40 s).
  3. Spider: ZAP rastrea el sitio para descubrir URLs y formularios.
  4. Active Scan: ZAP ataca cada punto encontrado buscando vulnerabilidades.
  5. Sondear el progreso hasta que ambos terminen (puede tardar bastante).
  6. Recoger las alertas (vulnerabilidades encontradas).
  7. Apagar el daemon y limpiar.

Como es pesado (consume RAM y tiempo), este modulo:
  - Tiene timeouts en cada etapa para no colgarse.
  - Se asegura de APAGAR ZAP siempre, incluso si algo falla (bloque finally).
  - Es configurable desde config.yaml (seccion 'zap').

Patron de siempre:
    def ejecutar(config, logger) -> list[Hallazgo]
"""

import logging
import os
import subprocess
import time

from core.modelo_hallazgo import Hallazgo, Severidad


ORIGEN = "modulo_zap"

# Puerto en el que levantaremos el daemon de ZAP (su API).
PUERTO_ZAP = 8090

# API key fija para hablar con nuestro propio ZAP local.
API_KEY = "auditoria-web-zap-key"

# Timeouts (segundos).
TIMEOUT_ARRANQUE = 120     # esperar a que el daemon arranque
TIMEOUT_SPIDER = 300       # esperar a que el spider termine
TIMEOUT_ASCAN = 900        # esperar a que el active scan termine (15 min)

# Mapeo del riesgo de ZAP a nuestra escala de severidad.
MAPA_RIESGO = {
    "High": Severidad.ALTA,
    "Medium": Severidad.MEDIA,
    "Low": Severidad.BAJA,
    "Informational": Severidad.INFORMATIVA,
}

# Mapeo aproximado de tipos de alerta de ZAP a categoria OWASP, por palabras
# clave en el nombre de la alerta.
def _categoria_desde_alerta(nombre: str) -> str:
    n = nombre.lower()
    if any(k in n for k in ["sql injection", "sqli"]):
        return "A03"
    if any(k in n for k in ["cross site scripting", "xss"]):
        return "A03"
    if any(k in n for k in ["injection", "command", "code inject", "xxe", "ldap"]):
        return "A03"
    if any(k in n for k in ["ssrf", "server side request"]):
        return "A10"
    if any(k in n for k in ["path traversal", "directory", "remote file"]):
        return "A01"
    if any(k in n for k in ["authentication", "session", "cookie", "login"]):
        return "A07"
    if any(k in n for k in ["csp", "header", "clickjack", "x-frame",
                            "content type", "cache"]):
        return "A05"
    if any(k in n for k in ["tls", "ssl", "certificate", "cipher", "https"]):
        return "A02"
    if any(k in n for k in ["outdated", "vulnerable js", "version"]):
        return "A06"
    # Por defecto, la mayoria de alertas de ZAP son de mala configuracion.
    return "A05"


def ejecutar(config: dict, logger: logging.Logger) -> list[Hallazgo]:
    """
    Punto de entrada del modulo (lo llama main.py).

    Levanta ZAP, escanea el objetivo y convierte las alertas en Hallazgos.
    Garantiza apagar ZAP al final pase lo que pase.
    """
    objetivo = config["objetivo"]["url"].strip()
    conf_zap = config.get("zap", {})
    ruta_zap = conf_zap.get("ruta")  # ruta a zap.sh (obligatoria)
    puerto = conf_zap.get("puerto", PUERTO_ZAP)
    timeout_ascan = conf_zap.get("timeout_ascan", TIMEOUT_ASCAN)
    timeout_spider = conf_zap.get("timeout_spider", TIMEOUT_SPIDER)
    active_scan = conf_zap.get("active_scan", True)

    hallazgos: list[Hallazgo] = []

    # --- Verificar que tenemos la ruta a zap.sh ---
    if not ruta_zap:
        logger.error(
            "[zap] No se ha definido la ruta a zap.sh en config.yaml "
            "(seccion 'zap: ruta'). Ejemplo: "
            "ruta: '/home/usuario/proyectos/ZAP_2.17.0/zap.sh'. Se omite el modulo."
        )
        return hallazgos

    if not os.path.isfile(ruta_zap):
        logger.error(f"[zap] No se encontro zap.sh en: {ruta_zap}. Se omite.")
        return hallazgos

    # --- Verificar la libreria ---
    try:
        from zapv2 import ZAPv2
    except ImportError:
        logger.error(
            "[zap] La libreria 'zaproxy' no esta instalada. "
            "Instalala con: pip install zaproxy. Se omite el modulo."
        )
        return hallazgos

    proceso_zap = None
    try:
        # --- Paso 1: lanzar el daemon de ZAP ---
        logger.info(f"[zap] Lanzando ZAP en modo daemon (puerto {puerto})...")
        proceso_zap = _lanzar_daemon(ruta_zap, puerto, logger)
        if proceso_zap is None:
            return hallazgos

        # --- Paso 2: conectar a la API y esperar a que arranque ---
        zap = ZAPv2(
            apikey=API_KEY,
            proxies={
                "http": f"http://127.0.0.1:{puerto}",
                "https": f"http://127.0.0.1:{puerto}",
            },
        )
        if not _esperar_arranque(zap, logger):
            logger.error("[zap] ZAP no arranco a tiempo. Se omite el modulo.")
            return hallazgos

        # --- Paso 3: acceder a la URL objetivo ---
        logger.info(f"[zap] Accediendo al objetivo: {objetivo}")
        zap.core.access_url(objetivo)
        time.sleep(2)

        # --- Paso 4: Spider (descubrir URLs) ---
        _ejecutar_spider(zap, objetivo, timeout_spider, logger)

        # --- Paso 5: Active Scan (atacar) ---
        if active_scan:
            _ejecutar_active_scan(zap, objetivo, timeout_ascan, logger)
        else:
            logger.info(
                "[zap] Active scan desactivado en config. Solo se usara el "
                "escaneo pasivo (menos hallazgos, pero mas rapido)."
            )
            time.sleep(5)  # dar tiempo al escaneo pasivo

        # --- Paso 6: recoger alertas ---
        hallazgos = _recoger_alertas(zap, objetivo, logger)

    except Exception as e:
        logger.error(f"[zap] Error durante el escaneo con ZAP: {e}")
    finally:
        # --- Paso 7: apagar ZAP SIEMPRE ---
        _apagar_daemon(proceso_zap, logger)

    logger.info(f"[zap] Analisis terminado. {len(hallazgos)} hallazgo(s).")
    return hallazgos


def _lanzar_daemon(ruta_zap, puerto, logger):
    """Lanza ZAP en modo daemon como subproceso. Devuelve el proceso o None."""
    comando = [
        ruta_zap,
        "-daemon",                       # modo sin interfaz
        "-host", "127.0.0.1",
        "-port", str(puerto),
        "-config", f"api.key={API_KEY}",
        # Permitir peticiones de la API con cualquier host header. La libreria
        # zapv2 envia las peticiones a 'http://zap/...', y ZAP 2.17 las rechaza
        # por defecto ('host header zap not permitted'). Estas dos lineas le
        # dicen a ZAP que acepte esas peticiones.
        "-config", "api.addrs.addr.name=.*",
        "-config", "api.addrs.addr.regex=true",
    ]
    try:
        proceso = subprocess.Popen(
            comando,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return proceso
    except Exception as e:
        logger.error(f"[zap] No se pudo lanzar ZAP: {e}")
        return None


def _esperar_arranque(zap, logger) -> bool:
    """Sondea la API de ZAP hasta que responda o se agote el tiempo."""
    logger.info("[zap] Esperando a que ZAP arranque (puede tardar ~30-40 s)...")
    inicio = time.time()
    ultimo_error = None
    while time.time() - inicio < TIMEOUT_ARRANQUE:
        try:
            version = zap.core.version
            logger.info(f"[zap] ZAP listo (version {version}).")
            return True
        except Exception as e:
            ultimo_error = e
            time.sleep(3)
    # Si llegamos aqui, no arranco. Damos pistas del ultimo error.
    logger.error(
        f"[zap] ZAP no respondio a la API a tiempo. Ultimo error: {ultimo_error}"
    )
    return False


def _ejecutar_spider(zap, objetivo, timeout, logger):
    """Lanza el spider y espera a que termine."""
    logger.info("[zap] Iniciando spider (descubrimiento de URLs)...")
    scan_id = zap.spider.scan(objetivo)
    time.sleep(2)

    inicio = time.time()
    while time.time() - inicio < timeout:
        try:
            progreso = int(zap.spider.status(scan_id))
        except Exception:
            progreso = 0
        if progreso >= 100:
            break
        logger.info(f"[zap] Spider: {progreso}%")
        time.sleep(5)

    try:
        n_urls = len(zap.spider.results(scan_id))
        logger.info(f"[zap] Spider terminado. {n_urls} URL(s) descubierta(s).")
    except Exception:
        logger.info("[zap] Spider terminado.")


def _ejecutar_active_scan(zap, objetivo, timeout, logger):
    """Lanza el active scan y espera a que termine."""
    logger.info(
        "[zap] Iniciando active scan (ataque activo). Esto puede tardar "
        "bastante (hasta 15 min)..."
    )
    scan_id = zap.ascan.scan(objetivo)
    time.sleep(3)

    inicio = time.time()
    while time.time() - inicio < timeout:
        try:
            estado = zap.ascan.status(scan_id)
            progreso = int(estado)
        except Exception:
            progreso = 0
        if progreso >= 100:
            break
        logger.info(f"[zap] Active scan: {progreso}%")
        time.sleep(10)
    else:
        logger.warning(
            f"[zap] El active scan supero el timeout de {timeout}s. "
            f"Se recogen los resultados obtenidos hasta ahora."
        )

    logger.info("[zap] Active scan finalizado.")


def _recoger_alertas(zap, objetivo, logger) -> list[Hallazgo]:
    """Convierte las alertas de ZAP en objetos Hallazgo, sin duplicados."""
    hallazgos: list[Hallazgo] = []
    try:
        alertas = zap.core.alerts(baseurl=objetivo)
    except Exception as e:
        logger.error(f"[zap] No se pudieron recoger las alertas: {e}")
        return hallazgos

    # ZAP suele repetir la misma alerta en muchas URLs. Agrupamos por
    # (nombre, riesgo) para no inundar el reporte con duplicados.
    vistos = set()

    for alerta in alertas:
        nombre = alerta.get("alert", alerta.get("name", "Alerta de ZAP"))
        riesgo = alerta.get("risk", "Informational")
        url_alerta = alerta.get("url", objetivo)

        clave = (nombre, riesgo)
        if clave in vistos:
            continue
        vistos.add(clave)

        severidad = MAPA_RIESGO.get(riesgo, Severidad.INFORMATIVA)
        categoria = _categoria_desde_alerta(nombre)

        descripcion = (alerta.get("description", "") or "").strip()
        if not descripcion:
            descripcion = f"Alerta detectada por ZAP: {nombre}."
        # Truncar descripciones muy largas.
        if len(descripcion) > 500:
            descripcion = descripcion[:500].rsplit(" ", 1)[0] + " [...]"

        solucion = (alerta.get("solution", "") or "").strip()
        if len(solucion) > 400:
            solucion = solucion[:400].rsplit(" ", 1)[0] + " [...]"
        if not solucion:
            solucion = "Revisar la alerta y aplicar la correccion recomendada."

        # CVSS: ZAP no siempre lo da; usamos None y dejamos que el motor de
        # riesgo (Fase 5) lo estime por severidad si hace falta.
        parametro = alerta.get("param", "")
        evidencia_zap = alerta.get("evidence", "")
        evidencia = f"URL: {url_alerta}"
        if parametro:
            evidencia += f" | Parametro: {parametro}"
        if evidencia_zap:
            evidencia += f" | Evidencia: {evidencia_zap[:150]}"

        hallazgos.append(Hallazgo(
            titulo=nombre,
            categoria=categoria,
            severidad=severidad,
            descripcion=descripcion,
            cvss=None,
            evidencia=evidencia,
            recomendacion=solucion,
            herramienta_origen=ORIGEN,
            url_afectada=url_alerta,
        ))

    logger.info(
        f"[zap] {len(hallazgos)} alerta(s) unica(s) recogida(s) "
        f"(de {len(alertas)} en total, agrupadas)."
    )
    return hallazgos


def _apagar_daemon(proceso_zap, logger):
    """Apaga el daemon de ZAP de forma limpia. Se llama siempre (finally)."""
    if proceso_zap is None:
        return
    logger.info("[zap] Apagando ZAP...")
    try:
        proceso_zap.terminate()
        try:
            proceso_zap.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proceso_zap.kill()  # forzar si no responde
    except Exception as e:
        logger.warning(f"[zap] Problema al apagar ZAP: {e}")


# Prueba independiente:
#     python3 -m modulos.zap
# Requiere ZAP instalado y la ruta correcta a zap.sh.
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    log = logging.getLogger("prueba")

    config_prueba = {
        "objetivo": {"url": "http://scanme.nmap.org"},
        "opciones": {},
        "zap": {
            # AJUSTA esta ruta a la de tu instalacion:
            "ruta": os.path.expanduser("~/proyectos/ZAP_2.17.0/zap.sh"),
            "active_scan": True,
            "timeout_ascan": 600,
        },
    }

    print("Probando el modulo ZAP ...")
    print("(Levantara ZAP, escaneara, y lo apagara. Puede tardar varios minutos)\n")
    resultados = ejecutar(config_prueba, log)

    print(f"\nSe generaron {len(resultados)} hallazgos:\n")
    for h in resultados:
        print(h)
        print()