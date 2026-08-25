"""
main.py
Orquestador principal de la herramienta de auditoria.

Este es el punto de entrada del programa. Su trabajo es COORDINAR, no
detectar: el detectar es tarea de los modulos. main.py se encarga de:

  1. Leer la configuracion (config.yaml).
  2. Verificar que exista autorizacion para auditar (salvaguarda etica/legal).
  3. Preparar el sistema de logging.
  4. Ejecutar los modulos que esten activados en la config.
  5. Recoger todos los hallazgos en un unico Reporte.
  6. Guardar el reporte y mostrar el resumen.

En esta fase (Fase 1) todavia no hay modulos construidos, asi que el
programa corre "vacio": completa todo el ciclo y genera un reporte con
cero hallazgos. Eso confirma que el esqueleto funciona de punta a punta.
A partir de la Fase 2 iremos "enchufando" modulos reales.

Uso:
    python3 main.py
    python3 main.py --config otra_config.yaml
"""

import argparse
import logging
import sys

import yaml

# Importamos desde el paquete core. Para que esto funcione, core/ debe tener
# un archivo __init__.py (aunque este vacio) y main.py debe ejecutarse desde
# la raiz del proyecto.
from core.reporte import Reporte
from core.riesgo import MotorRiesgo


# CARGA Y VALIDACION DE LA CONFIGURACION

def cargar_config(ruta: str) -> dict:
    """
    Lee el archivo config.yaml y lo devuelve como diccionario.
    Termina el programa con un mensaje claro si el archivo no existe
    o tiene errores de formato.
    """
    try:
        with open(ruta, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
    except FileNotFoundError:
        print(f"[ERROR] No se encontro el archivo de configuracion: {ruta}")
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"[ERROR] El archivo de configuracion tiene un error de formato:")
        print(f"        {e}")
        sys.exit(1)

    if not config:
        print(f"[ERROR] El archivo de configuracion esta vacio: {ruta}")
        sys.exit(1)

    return config


def validar_config(config: dict) -> None:
    """
    Comprueba que la configuracion tenga lo minimo necesario para operar
    y que se cumplan las salvaguardas antes de tocar el objetivo.
    Termina el programa si algo esencial falta o no esta autorizado.
    """
    objetivo = config.get("objetivo", {})
    url = objetivo.get("url", "").strip()

    # 1. Debe haber una URL objetivo.
    if not url:
        print("[ERROR] No has definido una URL objetivo en config.yaml.")
        print("        Edita la seccion 'objetivo: url:' antes de ejecutar.")
        sys.exit(1)

    # 2. La URL debe incluir el esquema http:// o https://.
    if not (url.startswith("http://") or url.startswith("https://")):
        print(f"[ERROR] La URL debe empezar por http:// o https:// -> {url}")
        sys.exit(1)

    # 3. SALVAGUARDA: debe confirmarse la autorizacion.
    #    Esta es la barrera etica/legal del proyecto. Sin esto, no se ejecuta.
    if not objetivo.get("autorizacion_confirmada", False):
        print("[ERROR] Auditoria bloqueada: autorizacion no confirmada.")
        print("        Solo debes auditar objetivos que tengas permiso de auditar.")
        print("        Cuando tengas autorizacion, pon en config.yaml:")
        print("            objetivo:")
        print("              autorizacion_confirmada: true")
        sys.exit(1)


# LOGGING

def configurar_logging(config: dict) -> logging.Logger:
    """
    Prepara el sistema de logging segun la configuracion.
    Los mensajes se muestran en consola y, si se pide, tambien en archivo.
    """
    registro = config.get("registro", {})
    nivel_txt = registro.get("nivel", "INFO").upper()
    nivel = getattr(logging, nivel_txt, logging.INFO)

    logger = logging.getLogger("auditoria")
    logger.setLevel(nivel)
    logger.handlers.clear()  # evita duplicar handlers si se llama dos veces

    formato = logging.Formatter(
        "%(asctime)s  [%(levelname)s]  %(message)s",
        datefmt="%H:%M:%S",
    )

    # Handler de consola (siempre).
    consola = logging.StreamHandler()
    consola.setFormatter(formato)
    logger.addHandler(consola)

    # Handler de archivo (opcional).
    if registro.get("guardar_en_archivo", False):
        import os
        carpeta = config.get("salida", {}).get("carpeta", "resultados")
        os.makedirs(carpeta, exist_ok=True)
        archivo_log = os.path.join(carpeta, registro.get("archivo", "auditoria.log"))
        fh = logging.FileHandler(archivo_log, encoding="utf-8")
        fh.setFormatter(formato)
        logger.addHandler(fh)

    return logger


# EJECUCION DE MODULOS

def ejecutar_modulos(config: dict, reporte: Reporte, logger: logging.Logger) -> None:
    """
    Recorre los modulos activados en la config y ejecuta cada uno.

    Por ahora este es un ESQUELETO: los modulos aun no existen, asi que
    solo registramos cuales estarian activos. A medida que construyamos
    cada modulo en las siguientes fases, lo conectaremos aqui.

    El patron sera siempre el mismo:
        if modulos.get("cabeceras_http"):
            from modulos.cabeceras_http import ejecutar
            hallazgos = ejecutar(url, opciones, logger)
            reporte.agregar_varios(hallazgos)
    """
    modulos = config.get("modulos", {})
    activos = [nombre for nombre, on in modulos.items() if on]

    if not activos:
        logger.warning(
            "No hay ningun modulo activado en config.yaml. "
            "La auditoria correra vacia (0 hallazgos). Esto es lo esperado "
            "en la Fase 1 para probar el flujo."
        )
        return

    logger.info(f"Modulos activados: {', '.join(activos)}")

    # --- Modulo A05: cabeceras HTTP de seguridad ---
    if modulos.get("cabeceras_http"):
        logger.info("Ejecutando modulo: cabeceras_http")
        from modulos.cabeceras_http import ejecutar as ejecutar_cabeceras
        reporte.agregar_varios(ejecutar_cabeceras(config, logger))

    # --- Modulo A02: flags de seguridad en cookies ---
    if modulos.get("cookies"):
        logger.info("Ejecutando modulo: cookies")
        from modulos.cookies import ejecutar as ejecutar_cookies
        reporte.agregar_varios(ejecutar_cookies(config, logger))

     # --- Modulo A02: analisis TLS/SSL ---
    if modulos.get("tls_ssl"):
        logger.info("Ejecutando modulo: tls_ssl")
        from modulos.tls_ssl import ejecutar as ejecutar_tls
        reporte.agregar_varios(ejecutar_tls(config, logger))
    # --- Modulo A05: archivos y directorios sensibles expuestos ---
    if modulos.get("archivos_expuestos"):
        logger.info("Ejecutando modulo: archivos_expuestos")
        from modulos.archivos_expuestos import ejecutar as ejecutar_archivos
        reporte.agregar_varios(ejecutar_archivos(config, logger))
    # --- Modulo A06: deteccion de tecnologias y versiones ---
    if modulos.get("tecnologias"):
        logger.info("Ejecutando modulo: tecnologias")
        from modulos.tecnologias import ejecutar as ejecutar_tecnologias
        reporte.agregar_varios(ejecutar_tecnologias(config, logger))
    # --- Modulo A06/A10: escaneo con Nuclei ---
    if modulos.get("nuclei"):
        logger.info("Ejecutando modulo: nuclei")
        from modulos.nuclei import ejecutar as ejecutar_nuclei
        reporte.agregar_varios(ejecutar_nuclei(config, logger))
    # --- Modulo A05: escaneo de puertos con nmap ---
    if modulos.get("puertos_nmap"):
        logger.info("Ejecutando modulo: nmap")
        from modulos.nmap import ejecutar as ejecutar_nmap
        reporte.agregar_varios(ejecutar_nmap(config, logger))
     # --- Modulo Recon: crawler (rastreo del sitio) ---
    if modulos.get("crawler"):
        logger.info("Ejecutando modulo: crawler")
        from modulos.crawler import ejecutar as ejecutar_crawler
        reporte.agregar_varios(ejecutar_crawler(config, logger))
    # Pasar al modulo sqlmap las URLs con parametros que encontro el crawler.
    if modulos.get("crawler") and modulos.get("sqlmap"):
        import os
        ruta_urls = os.path.join(
            config.get("salida", {}).get("carpeta", "resultados"),
            "urls_con_parametros.txt"
        )
        if os.path.isfile(ruta_urls):
            with open(ruta_urls) as f:
                urls_crawler = [l.strip() for l in f if l.strip()]
            config.setdefault("sqlmap", {}).setdefault("urls", [])
            config["sqlmap"]["urls"].extend(urls_crawler)
            logger.info(
                f"Se añadieron {len(urls_crawler)} URLs del crawler a sqlmap."
            )
    # --- Modulo A03: inyeccion SQL con sqlmap ---
    if modulos.get("sqlmap"):
        logger.info("Ejecutando modulo: sqlmap")
        from modulos.sqlmap import ejecutar as ejecutar_sqlmap
        reporte.agregar_varios(ejecutar_sqlmap(config, logger))
    # --- Modulo A03 y otros: escaneo con OWASP ZAP ---
    if modulos.get("zap"):
        logger.info("Ejecutando modulo: zap")
        from modulos.zap import ejecutar as ejecutar_zap
        reporte.agregar_varios(ejecutar_zap(config, logger))
    # --- Modulo A01: metodos HTTP peligrosos y path traversal ---
    if modulos.get("metodos_http"):
        logger.info("Ejecutando modulo: metodos_http")
        from modulos.metodos_http import ejecutar as ejecutar_metodos
        reporte.agregar_varios(ejecutar_metodos(config, logger))
    # --- Modulo A07: analisis de autenticacion ---
    if modulos.get("autenticacion"):
        logger.info("Ejecutando modulo: autenticacion")
        from modulos.autenticacion import ejecutar as ejecutar_auth
        reporte.agregar_varios(ejecutar_auth(config, logger))


# FLUJO PRINCIPAL
def main():
    # Permite pasar --config para usar otro archivo de configuracion.
    parser = argparse.ArgumentParser(
        description="Herramienta de auditoria de seguridad web."
    )
    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Ruta al archivo de configuracion (por defecto: config.yaml)",
    )
    args = parser.parse_args()

    # 1. Cargar y validar configuracion.
    config = cargar_config(args.config)
    validar_config(config)

    # 2. Preparar logging.
    logger = configurar_logging(config)

    objetivo = config["objetivo"]
    url = objetivo["url"].strip()
    nombre = objetivo.get("nombre", "")

    logger.info("=" * 55)
    logger.info("  INICIO DE LA AUDITORIA")
    logger.info("=" * 55)
    logger.info(f"Objetivo: {url}")

    # 3. Crear el reporte que acumulara los hallazgos.
    reporte = Reporte(objetivo=url, nombre=nombre)

    # 4. Ejecutar los modulos activos.
    try:
        ejecutar_modulos(config, reporte, logger)
    except Exception as e:
        # Un modulo puede fallar sin que se caiga toda la auditoria.
        logger.error(f"Error inesperado durante la ejecucion: {e}")

    # --- Fase 5: analisis de riesgos sobre los hallazgos recogidos ---
    logger.info("Ejecutando analisis de riesgos...")
    motor = MotorRiesgo(reporte.hallazgos)
    analisis_riesgo = motor.analizar()
    logger.info(
        f"Riesgo global: {analisis_riesgo['valoracion_global']['nivel']} "
        f"({analisis_riesgo['valoracion_global']['puntuacion']}/10)"
    )
    reporte.set_analisis_riesgo(analisis_riesgo)

    # 5. Cerrar el reporte y guardarlo.
    reporte.finalizar()

    salida = config.get("salida", {})
    carpeta = salida.get("carpeta", "resultados")
    ruta = reporte.guardar_json(carpeta)

    # --- Fase 6: generar el informe HTML/PDF ---
    from core.reporte_html import generar as generar_informe
    formatos = salida.get("formatos", ["json"])
    formatos_informe = [f for f in formatos if f in ("html", "pdf")]
    if formatos_informe:
        datos = reporte.construir()
        rutas_informe = generar_informe(datos, carpeta, formatos_informe, logger)


    # 7. Mostrar resumen final.
    reporte.imprimir_resumen()
    logger.info(f"Reporte guardado en: {ruta}")
    logger.info("Auditoria finalizada.")


if __name__ == "__main__":
    main()