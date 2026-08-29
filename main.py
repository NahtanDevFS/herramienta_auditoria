"""
main.py
Punto de entrada por linea de comandos de la herramienta de auditoria.

Se encarga de:
  1. Leer la configuracion (config.yaml).
  2. Verificar que exista autorizacion para auditar (salvaguarda etica/legal).
  3. Preparar el sistema de logging.
  4. Delegar la ejecucion de la auditoria a auditoria.ejecutar_auditoria(),
     la misma funcion que usa la interfaz grafica (app_gui.py), para no
     duplicar la logica de orquestacion de modulos.
  5. Guardar el reporte y generar el informe HTML/PDF.

Uso:
    python3 main.py
    python3 main.py --config otra_config.yaml
"""

import argparse
import logging
import sys

import yaml

from auditoria import ejecutar_auditoria


def cargar_config(ruta: str) -> dict:
    """Lee config.yaml y lo devuelve como diccionario."""
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
    """
    objetivo = config.get("objetivo", {})
    url = objetivo.get("url", "").strip()

    if not url:
        print("[ERROR] No has definido una URL objetivo en config.yaml.")
        print("        Edita la seccion 'objetivo: url:' antes de ejecutar.")
        sys.exit(1)

    if not (url.startswith("http://") or url.startswith("https://")):
        print(f"[ERROR] La URL debe empezar por http:// o https:// -> {url}")
        sys.exit(1)

    # SALVAGUARDA: debe confirmarse la autorizacion. Sin esto, no se ejecuta.
    if not objetivo.get("autorizacion_confirmada", False):
        print("[ERROR] Auditoria bloqueada: autorizacion no confirmada.")
        print("        Solo debes auditar objetivos que tengas permiso de auditar.")
        print("        Cuando tengas autorizacion, pon en config.yaml:")
        print("            objetivo:")
        print("              autorizacion_confirmada: true")
        sys.exit(1)


def configurar_logging(config: dict) -> logging.Logger:
    """Prepara el logging (consola y, si se pide, archivo)."""
    registro = config.get("registro", {})
    nivel_txt = registro.get("nivel", "INFO").upper()
    nivel = getattr(logging, nivel_txt, logging.INFO)

    logger = logging.getLogger("auditoria")
    logger.setLevel(nivel)
    logger.handlers.clear()

    formato = logging.Formatter(
        "%(asctime)s  [%(levelname)s]  %(message)s",
        datefmt="%H:%M:%S",
    )

    consola = logging.StreamHandler()
    consola.setFormatter(formato)
    logger.addHandler(consola)

    if registro.get("guardar_en_archivo", False):
        import os
        carpeta = config.get("salida", {}).get("carpeta", "resultados")
        os.makedirs(carpeta, exist_ok=True)
        archivo_log = os.path.join(carpeta, registro.get("archivo", "auditoria.log"))
        fh = logging.FileHandler(archivo_log, encoding="utf-8")
        fh.setFormatter(formato)
        logger.addHandler(fh)

    return logger


def main():
    parser = argparse.ArgumentParser(
        description="Herramienta de auditoria de seguridad web."
    )
    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Ruta al archivo de configuracion (por defecto: config.yaml)",
    )
    args = parser.parse_args()

    config = cargar_config(args.config)
    validar_config(config)

    logger = configurar_logging(config)

    url = config["objetivo"]["url"].strip()

    logger.info("=" * 55)
    logger.info("  INICIO DE LA AUDITORIA")
    logger.info("=" * 55)
    logger.info(f"Objetivo: {url}")

    try:
        reporte = ejecutar_auditoria(config, logger)
    except Exception as e:
        logger.error(f"Error inesperado durante la ejecucion: {e}")
        sys.exit(1)

    salida = config.get("salida", {})
    carpeta = salida.get("carpeta", "resultados")
    ruta = reporte.guardar_json(carpeta)

    from core.reporte_html import generar as generar_informe
    formatos = salida.get("formatos", ["json"])
    formatos_informe = [f for f in formatos if f in ("html", "pdf")]
    if formatos_informe:
        datos = reporte.construir()
        generar_informe(datos, carpeta, formatos_informe, logger)

    reporte.imprimir_resumen()
    logger.info(f"Reporte guardado en: {ruta}")
    logger.info("Auditoria finalizada.")


if __name__ == "__main__":
    main()