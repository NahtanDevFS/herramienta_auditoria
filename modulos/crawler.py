"""
crawler.py  (modulo de reconocimiento - Recon / base para A05)
Rastrea el sitio objetivo siguiendo enlaces internos para descubrir:
  - Rutas / paginas (el "mapa" del sitio).
  - Formularios (posibles puntos de entrada de datos).
  - Parametros (en URLs con ?param= y en campos de formulario).

Su valor es doble:
  1. Genera hallazgos informativos: el inventario de rutas y formularios es
     parte del reconocimiento de activos (uno de los objetivos del proyecto).
  2. Produce una lista de URLs CON PARAMETROS que otros modulos (sobre todo
     sqlmap) pueden usar como objetivos de inyeccion. Esa lista se guarda en
     un archivo para que main.py pueda pasarla a sqlmap.

Es un crawler EDUCADO y ACOTADO:
  - Solo sigue enlaces del MISMO dominio (no se va a sitios externos).
  - Respeta un limite de paginas y de profundidad (configurable).
  - Hace una pausa minima entre peticiones para no saturar el servidor.

Patron de siempre:
    def ejecutar(config, logger) -> list[Hallazgo]
"""

import logging
import os
import time
from collections import deque
from urllib.parse import urljoin, urlparse, urldefrag

import requests
from bs4 import BeautifulSoup

from core.modelo_hallazgo import Hallazgo


ORIGEN = "modulo_crawler"

# Limites por defecto (configurables desde config.yaml).
MAX_PAGINAS_DEFECTO = 50      # cuantas paginas visitar como maximo
MAX_PROFUNDIDAD_DEFECTO = 3   # cuantos niveles de enlaces seguir
PAUSA_ENTRE_PETICIONES = 0.3  # segundos entre peticiones (ser educado)

# Extensiones de archivo que no tiene sentido rastrear (binarios, media).
EXTENSIONES_IGNORAR = {
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".webp",
    ".css", ".js", ".pdf", ".zip", ".tar", ".gz", ".mp4", ".mp3",
    ".woff", ".woff2", ".ttf", ".eot",
}


def ejecutar(config: dict, logger: logging.Logger) -> list[Hallazgo]:
    """
    Punto de entrada del modulo (lo llama main.py).

    Rastrea el sitio y devuelve hallazgos informativos con el mapa del sitio,
    los formularios y las URLs con parametros. Ademas guarda las URLs con
    parametros en un archivo para que sqlmap las use.
    """
    objetivo = config["objetivo"]["url"].strip()
    opciones = config.get("opciones", {})
    conf_crawler = config.get("crawler", {})

    max_paginas = conf_crawler.get("max_paginas", MAX_PAGINAS_DEFECTO)
    max_profundidad = conf_crawler.get("max_profundidad", MAX_PROFUNDIDAD_DEFECTO)
    timeout = opciones.get("timeout", 10)
    verificar_ssl = opciones.get("verificar_ssl", True)
    user_agent = opciones.get("user_agent", "AuditoriaWeb/1.0")

    logger.info(
        f"[crawler] Iniciando rastreo de {objetivo} "
        f"(max {max_paginas} paginas, profundidad {max_profundidad})"
    )

    dominio = urlparse(objetivo).netloc

    # Estructuras de datos del rastreo.
    visitadas = set()
    urls_con_parametros = set()
    formularios = []          # lista de dicts: {url, action, method, campos}
    firmas_formularios = set()  # para deduplicar formularios repetidos
    rutas_descubiertas = set()

    # Cola de trabajo: (url, profundidad). Usamos BFS.
    cola = deque([(objetivo, 0)])

    sesion = requests.Session()
    sesion.headers.update({"User-Agent": user_agent})

    while cola and len(visitadas) < max_paginas:
        url, profundidad = cola.popleft()

        # Normalizar: quitar el fragmento (#...).
        url, _ = urldefrag(url)

        if url in visitadas:
            continue
        if profundidad > max_profundidad:
            continue

        # Pedir la pagina.
        try:
            resp = sesion.get(url, timeout=timeout, verify=verificar_ssl,
                              allow_redirects=True)
        except requests.exceptions.RequestException as e:
            logger.debug(f"[crawler] No se pudo acceder a {url}: {e}")
            continue

        visitadas.add(url)
        rutas_descubiertas.add(url)

        # ¿Esta URL tiene parametros? (?algo=valor)
        if urlparse(url).query:
            urls_con_parametros.add(url)

        # Solo parseamos HTML.
        tipo = resp.headers.get("Content-Type", "")
        if "text/html" not in tipo:
            continue

        # Parsear el HTML.
        try:
            sopa = BeautifulSoup(resp.text, "html.parser")
        except Exception as e:
            logger.debug(f"[crawler] Error al parsear {url}: {e}")
            continue

        #Extraer formularios
        for form in sopa.find_all("form"):
            datos_form = _extraer_formulario(form, url)
            if datos_form:
                # Deduplicar: un mismo formulario (header/footer) aparece en
                # muchas paginas. Lo identificamos por su action + metodo +
                # campos, y solo lo registramos una vez.
                firma = (
                    datos_form["action"],
                    datos_form["metodo"],
                    tuple(c["nombre"] for c in datos_form["campos"]),
                )
                if firma not in firmas_formularios:
                    firmas_formularios.add(firma)
                    formularios.append(datos_form)

        #Extraer enlaces y encolarlos
        for a in sopa.find_all("a", href=True):
            enlace = urljoin(url, a["href"])
            enlace, _ = urldefrag(enlace)

            # Solo seguir enlaces del mismo dominio.
            if urlparse(enlace).netloc != dominio:
                continue
            # Ignorar archivos binarios/media.
            if _tiene_extension_ignorada(enlace):
                continue

            # Si tiene parametros, registrarla aunque no la visitemos entera.
            if urlparse(enlace).query:
                urls_con_parametros.add(enlace)

            if enlace not in visitadas:
                cola.append((enlace, profundidad + 1))

        time.sleep(PAUSA_ENTRE_PETICIONES)

    logger.info(
        f"[crawler] Rastreo terminado. {len(visitadas)} pagina(s) visitada(s), "
        f"{len(formularios)} formulario(s), "
        f"{len(urls_con_parametros)} URL(s) con parametros."
    )

    #Guardar URLs con parametros para sqlmap
    _guardar_urls_para_sqlmap(urls_con_parametros, config, logger)

    #Construir hallazgos
    return _construir_hallazgos(
        objetivo, rutas_descubiertas, formularios, urls_con_parametros, logger
    )


def _extraer_formulario(form, url_pagina) -> dict | None:
    """Extrae la informacion relevante de un formulario HTML."""
    action = form.get("action", "")
    metodo = form.get("method", "get").upper()
    action_completa = urljoin(url_pagina, action) if action else url_pagina

    campos = []
    for input_el in form.find_all(["input", "textarea", "select"]):
        nombre = input_el.get("name")
        tipo = input_el.get("type", "text")
        if nombre:
            campos.append({"nombre": nombre, "tipo": tipo})

    if not campos:
        return None

    return {
        "pagina": url_pagina,
        "action": action_completa,
        "metodo": metodo,
        "campos": campos,
    }


def _tiene_extension_ignorada(url: str) -> bool:
    """True si la URL apunta a un archivo que no tiene sentido rastrear."""
    ruta = urlparse(url).path.lower()
    return any(ruta.endswith(ext) for ext in EXTENSIONES_IGNORAR)


def _guardar_urls_para_sqlmap(urls, config, logger) -> None:
    """
    Guarda las URLs con parametros en un archivo de texto, para que main.py
    pueda pasarselas a sqlmap. Una URL por linea.
    """
    if not urls:
        return
    carpeta = config.get("salida", {}).get("carpeta", "resultados")
    os.makedirs(carpeta, exist_ok=True)
    ruta = os.path.join(carpeta, "urls_con_parametros.txt")
    try:
        with open(ruta, "w", encoding="utf-8") as f:
            for url in sorted(urls):
                f.write(url + "\n")
        logger.info(
            f"[crawler] {len(urls)} URL(s) con parametros guardadas en {ruta} "
            f"(disponibles para sqlmap)."
        )
    except OSError as e:
        logger.warning(f"[crawler] No se pudieron guardar las URLs: {e}")


def _construir_hallazgos(objetivo, rutas, formularios, urls_param, logger):
    """Crea los hallazgos informativos a partir de lo descubierto."""
    hallazgos = []

    # 1. Mapa del sitio (rutas descubiertas).
    if rutas:
        # Mostrar solo las rutas (path), no la URL completa, para legibilidad.
        paths = sorted({urlparse(r).path or "/" for r in rutas})
        muestra = paths[:40]
        resumen = ", ".join(muestra)
        if len(paths) > 40:
            resumen += f" ... (+{len(paths) - 40} mas)"

        hallazgos.append(Hallazgo(
            titulo=f"Mapa del sitio: {len(rutas)} ruta(s) descubierta(s)",
            categoria="A05",
            severidad="informativa",
            descripcion=(
                "Inventario de rutas descubiertas durante el rastreo del sitio. "
                "Forma parte del reconocimiento de la superficie de ataque."
            ),
            cvss=None,
            evidencia=f"Rutas: {resumen}",
            recomendacion=(
                "Revisar que no haya rutas sensibles o de administracion "
                "accesibles sin autenticacion."
            ),
            herramienta_origen=ORIGEN,
            url_afectada=objetivo,
        ))

    # 2. Formularios encontrados (puntos de entrada de datos).
    if formularios:
        lineas = []
        for f in formularios[:15]:
            nombres = ", ".join(c["nombre"] for c in f["campos"])
            lineas.append(f"{f['metodo']} {f['action']} [campos: {nombres}]")
        resumen = " ; ".join(lineas)
        if len(formularios) > 15:
            resumen += f" ... (+{len(formularios) - 15} mas)"

        hallazgos.append(Hallazgo(
            titulo=f"Formularios detectados: {len(formularios)}",
            categoria="A05",
            severidad="informativa",
            descripcion=(
                "Formularios encontrados en el sitio. Son puntos de entrada de "
                "datos y, por tanto, posibles vectores de inyeccion (SQLi, XSS) "
                "que conviene probar."
            ),
            cvss=None,
            evidencia=resumen,
            recomendacion=(
                "Validar y sanitizar toda entrada de estos formularios en el "
                "servidor. Verificar proteccion CSRF."
            ),
            herramienta_origen=ORIGEN,
            url_afectada=objetivo,
        ))

    # 3. URLs con parametros (objetivos para pruebas de inyeccion).
    if urls_param:
        muestra = sorted(urls_param)[:20]
        resumen = "; ".join(muestra)
        if len(urls_param) > 20:
            resumen += f" ... (+{len(urls_param) - 20} mas)"

        hallazgos.append(Hallazgo(
            titulo=f"URLs con parametros: {len(urls_param)}",
            categoria="A05",
            severidad="informativa",
            descripcion=(
                "URLs con parametros de entrada. Son los principales candidatos "
                "para pruebas de inyeccion SQL y otros ataques de inyeccion. "
                "Se han guardado para su uso con sqlmap."
            ),
            cvss=None,
            evidencia=f"URLs: {resumen}",
            recomendacion=(
                "Asegurar que todos los parametros se validan y se usan en "
                "consultas parametrizadas."
            ),
            herramienta_origen=ORIGEN,
            url_afectada=objetivo,
        ))

    logger.info(f"[crawler] {len(hallazgos)} hallazgo(s) informativo(s) generado(s).")
    return hallazgos


# Prueba independiente:
#     python3 -m modulos.crawler
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    log = logging.getLogger("prueba")

    config_prueba = {
        "objetivo": {"url": "http://scanme.nmap.org"},
        "opciones": {"timeout": 10, "verificar_ssl": True},
        "salida": {"carpeta": "resultados_prueba"},
        "crawler": {"max_paginas": 20, "max_profundidad": 2},
    }

    print("Probando el modulo crawler contra scanme.nmap.org ...\n")
    resultados = ejecutar(config_prueba, log)

    print(f"\nSe generaron {len(resultados)} hallazgos:\n")
    for h in resultados:
        print(h)
        print(f"    Evidencia: {h.evidencia[:200]}")
        print()