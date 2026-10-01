# rate_limit.py - Sonda ACOTADA de limite de tasa (A07). NO es un DoS.
#
# Envia una rafaga fija y pequena de peticiones GET al objetivo y comprueba si el
# servidor las limita (429 / 503 / cabecera Retry-After). Mide la EXISTENCIA del
# control, no intenta derribar nada:
#   - numero fijo y bajo de peticiones (30 por defecto), secuenciales.
#   - se autodetiene si el servidor da senales de estres (varios fallos seguidos).
#   - requiere autorizacion confirmada, igual que el resto de pruebas activas.
#
# Se ejecuta de ULTIMO en el pipeline (ver ORDEN_MODULOS) por si el servidor
# bloquea la IP tras la rafaga: asi no afecta a los demas modulos. Es opcional
# (casilla propia en la interfaz).

import logging

import requests

from core.modelo_hallazgo import Hallazgo

ORIGEN = "modulo_rate_limit"

N_PETICIONES_DEFECTO = 100   # rafaga acotada (configurable via rate_limit.peticiones)
TIMEOUT_PETICION = 5


def ejecutar(config: dict, logger: logging.Logger) -> list[Hallazgo]:
    objetivo = config.get("objetivo", {})
    if not objetivo.get("autorizacion_confirmada", False):
        logger.error("[rate_limit] Autorizacion no confirmada. Modulo no ejecutado.")
        return []

    url = (objetivo.get("url") or "").strip()
    if not url:
        logger.error("[rate_limit] No hay URL objetivo.")
        return []

    opciones = config.get("opciones", {})
    verificar_ssl = opciones.get("verificar_ssl", True)
    n = config.get("rate_limit", {}).get("peticiones", N_PETICIONES_DEFECTO)

    logger.info(f"[rate_limit] Sondeo acotado de limite de tasa: {n} peticiones a {url}")

    codigos: dict[int, int] = {}
    limitado = False
    fallos_seguidos = 0
    enviadas = 0

    for i in range(n):
        try:
            r = requests.get(url, timeout=TIMEOUT_PETICION, verify=verificar_ssl,
                             headers={"User-Agent": "AuditoriaWeb/1.0 (rate-check)"})
            enviadas += 1
            codigos[r.status_code] = codigos.get(r.status_code, 0) + 1
            if r.status_code in (429, 503) or r.headers.get("Retry-After"):
                limitado = True
                logger.info(f"[rate_limit] Rate limiting detectado en la peticion "
                            f"{i + 1} (HTTP {r.status_code}).")
                break
            fallos_seguidos = 0
        except requests.exceptions.RequestException:
            fallos_seguidos += 1
            # el servidor da senales de estres: paramos para no apilar carga
            if fallos_seguidos >= 5:
                logger.warning("[rate_limit] El servidor dejo de responder; se aborta el "
                               "sondeo (prueba no concluyente).")
                return []

    if limitado:
        logger.info("[rate_limit] Rate limiting presente; no se registra hallazgo.")
        return []

    resumen = ", ".join(f"{c}x HTTP {k}" for k, c in sorted(codigos.items()))
    logger.info(f"[rate_limit] Sin limite de tasa tras {enviadas} peticiones "
                f"({resumen or 'sin respuestas'}).")
    return [Hallazgo(
        titulo="Sin limite de tasa (rate limiting) en el servidor",
        categoria="A07", severidad="media", cvss=5.3,
        descripcion="El servidor acepto una rafaga de peticiones sin aplicar ningun "
                    "limite de tasa. Esto facilita ataques de fuerza bruta, enumeracion "
                    "y abuso/scraping de la API.",
        evidencia=f"{enviadas} peticiones consecutivas a {url} sin respuesta 429/503 ni "
                  f"cabecera Retry-After. Codigos observados: {resumen or 'ninguno'}.",
        recomendacion="Aplicar rate limiting por IP/usuario (por ejemplo 429 con "
                      "Retry-After) y proteger el login y los endpoints de API contra "
                      "fuerza bruta.",
        herramienta_origen=ORIGEN,
        url_afectada=url,
    )]


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    cfg = {"objetivo": {"url": "https://example.com", "autorizacion_confirmada": True},
           "opciones": {}, "rate_limit": {"peticiones": 5}}
    for h in ejecutar(cfg, logging.getLogger("prueba")):
        print(h)
