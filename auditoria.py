# ejecuta la auditoria desde dict config, reutilizable en cli/gui

import logging
import os

from core.reporte import Reporte
from core.riesgo import MotorRiesgo


# orden de ejecucion de modulos importados perezosamente
ORDEN_MODULOS = [
    ("cabeceras_http", "cabeceras_http"),
    ("cookies", "cookies"),
    ("tls_ssl", "tls_ssl"),
    ("archivos_expuestos", "archivos_expuestos"),
    ("tecnologias", "tecnologias"),
    ("nuclei", "nuclei"),
    ("puertos_nmap", "nmap"),
    ("crawler", "crawler"),
    ("sqlmap", "sqlmap"),
    ("zap", "zap"),
    ("metodos_http", "metodos_http"),
    ("autenticacion", "autenticacion"),
    ("agente_ia", "agente_pentesting"),
]


def ejecutar_auditoria(config: dict, logger: logging.Logger,
                       callback_progreso=None) -> dict:
    # ejecuta la auditoria completa segun la configuracion dada y devuelve
    # el reporte construido con hallazgos + analisis de riesgo
    objetivo = config["objetivo"]
    url = objetivo["url"].strip()
    nombre = objetivo.get("nombre", "")

    logger.info(f"Iniciando auditoria de {url}")

    reporte = Reporte(objetivo=url, nombre=nombre)

    modulos_cfg = config.get("modulos", {})
    # filtrar los modulos activos, respetando el orden de ejecucion
    activos = [(clave, mod) for clave, mod in ORDEN_MODULOS
               if modulos_cfg.get(clave)]
    total = len(activos)

    for i, (clave, nombre_modulo) in enumerate(activos):
        if callback_progreso:
            callback_progreso(i, total, nombre_modulo)

        # antes de sqlmap, pasarle las urls con parametros del crawler
        if nombre_modulo == "sqlmap":
            _alimentar_sqlmap_con_crawler(config, logger)

        # antes del agente de IA, pasarle los hallazgos ya acumulados
        if nombre_modulo == "agente_pentesting":
            config["_hallazgos_previos"] = [h.to_dict() for h in reporte.hallazgos]

        logger.info(f"Ejecutando modulo: {nombre_modulo}")
        try:
            modulo = __import__(f"modulos.{nombre_modulo}",
                                fromlist=["ejecutar"])
            hallazgos = modulo.ejecutar(config, logger)
            reporte.agregar_varios(hallazgos)
        except Exception as e:
            logger.error(f"Error en el modulo {nombre_modulo}: {e}")

    # resumen de cierre del agente de IA (bitacora + narrativa), si lo genero
    if config.get("_resumen_agente"):
        reporte.set_resumen_agente(config["_resumen_agente"])

    if callback_progreso:
        callback_progreso(total, total, "analisis de riesgo")

    # analisis de riesgo
    logger.info("Ejecutando analisis de riesgos...")
    motor = MotorRiesgo(reporte.hallazgos)
    analisis = motor.analizar()
    reporte.set_analisis_riesgo(analisis)
    logger.info(
        f"Riesgo global: {analisis['valoracion_global']['nivel']} "
        f"({analisis['valoracion_global']['puntuacion']}/10)"
    )

    reporte.finalizar()
    return reporte


def _alimentar_sqlmap_con_crawler(config, logger):
    # pasa a sqlmap las urls con parametros que descubrio el crawler
    ruta_urls = os.path.join(
        config.get("salida", {}).get("carpeta", "resultados"),
        "urls_con_parametros.txt"
    )
    if os.path.isfile(ruta_urls):
        with open(ruta_urls) as f:
            urls = [l.strip() for l in f if l.strip()]
        if urls:
            config.setdefault("sqlmap", {}).setdefault("urls", [])
            config["sqlmap"]["urls"].extend(urls)
            logger.info(f"Se añadieron {len(urls)} URLs del crawler a sqlmap.")