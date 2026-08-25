"""
reporte_html.py  (generador de reporte HTML/PDF - Fase 6)
Toma el reporte consolidado (hallazgos + analisis de riesgo) y produce un
informe profesional en HTML y, opcionalmente, en PDF.

El informe incluye:
  - Portada con metadatos de la auditoria.
  - Resumen ejecutivo con la valoracion global de riesgo.
  - Grafico de distribucion de hallazgos por severidad.
  - Matriz de riesgo (probabilidad x impacto) visual.
  - Hallazgos agrupados por categoria OWASP, ordenados por severidad.

Usa Jinja2 para la plantilla (separar logica de presentacion) y WeasyPrint
para convertir el HTML a PDF (respeta el CSS, asi que el PDF se ve igual de
bien que el HTML).

Se llama con:
    generar(datos_reporte, carpeta, formatos, logger)
donde 'datos_reporte' es el dict que produce Reporte.construir().
"""

import logging
import os
from datetime import datetime

from jinja2 import Template


# Colores por severidad (se usan en el HTML/CSS).
COLOR_SEVERIDAD = {
    "critica": "#8B0000",
    "alta": "#D32F2F",
    "media": "#F57C00",
    "baja": "#FBC02D",
    "informativa": "#0288D1",
}

# Color de cada celda de la matriz segun su nivel de riesgo.
COLOR_NIVEL = {
    "Critico": "#8B0000",
    "Alto": "#D32F2F",
    "Medio": "#F57C00",
    "Bajo": "#FBC02D",
    "Informativo": "#90A4AE",
}


# Plantilla HTML del informe (Jinja2). El CSS esta embebido para que el
# archivo sea autocontenido y WeasyPrint lo renderice bien a PDF.
PLANTILLA = Template(r"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>Informe de Auditoria de Seguridad - {{ meta.nombre }}</title>
<style>
  @page { size: A4; margin: 2cm; }
  * { box-sizing: border-box; }
  body {
    font-family: 'Segoe UI', Arial, sans-serif;
    color: #263238; line-height: 1.5; margin: 0; font-size: 12px;
  }
  h1, h2, h3 { color: #1A237E; margin-top: 1.2em; }
  h1 { font-size: 26px; border-bottom: 3px solid #1A237E; padding-bottom: 8px; }
  h2 { font-size: 19px; border-bottom: 1px solid #C5CAE9; padding-bottom: 4px; }
  h3 { font-size: 15px; }

  .portada {
    text-align: center; padding: 60px 20px; page-break-after: always;
  }
  .portada .titulo { font-size: 34px; color: #1A237E; font-weight: bold; }
  .portada .sub { font-size: 16px; color: #546E7A; margin-top: 10px; }
  .portada .meta { margin-top: 40px; font-size: 13px; color: #37474F; }
  .portada .meta div { margin: 6px 0; }

  .badge {
    display: inline-block; padding: 3px 10px; border-radius: 4px;
    color: white; font-weight: bold; font-size: 11px;
  }

  .valoracion {
    text-align: center; padding: 25px; border-radius: 8px; margin: 20px 0;
    color: white;
  }
  .valoracion .puntuacion { font-size: 48px; font-weight: bold; }
  .valoracion .nivel { font-size: 20px; text-transform: uppercase; }

  table { width: 100%; border-collapse: collapse; margin: 12px 0; }
  th, td { border: 1px solid #CFD8DC; padding: 6px 8px; text-align: left; }
  th { background: #E8EAF6; color: #1A237E; }

  .barra-cont { background: #ECEFF1; border-radius: 3px; height: 22px; position: relative; }
  .barra { height: 22px; border-radius: 3px; color: white; font-size: 11px;
           line-height: 22px; padding-left: 6px; white-space: nowrap; }

  /* Matriz de riesgo */
  .matriz { border-collapse: collapse; margin: 15px auto; }
  .matriz td, .matriz th { width: 70px; height: 55px; text-align: center;
    vertical-align: middle; border: 1px solid #fff; font-weight: bold; }
  .matriz .eje { background: #E8EAF6; color: #1A237E; font-size: 11px;
    width: 45px; }
  .matriz .celda { color: white; font-size: 13px; }
  .matriz .celda .n { font-size: 18px; }

  .hallazgo {
    border: 1px solid #CFD8DC; border-left: 5px solid #999;
    border-radius: 4px; padding: 12px 15px; margin: 12px 0;
    page-break-inside: avoid;
  }
  .hallazgo h4 { margin: 0 0 6px 0; font-size: 14px; color: #263238; }
  .hallazgo .campo { margin: 4px 0; font-size: 11.5px; }
  .hallazgo .etiqueta { font-weight: bold; color: #546E7A; }
  .hallazgo .evidencia {
    background: #F5F5F5; padding: 6px 8px; border-radius: 3px;
    font-family: 'Consolas', monospace; font-size: 10.5px;
    word-break: break-all; margin-top: 4px;
  }

  .categoria-seccion { page-break-inside: avoid; }
  .footer-nota { margin-top: 40px; padding-top: 12px; border-top: 1px solid #CFD8DC;
    font-size: 10px; color: #90A4AE; }
</style>
</head>
<body>

<!-- ===================== PORTADA ===================== -->
<div class="portada">
  <div class="titulo">Informe de Auditoria de Seguridad Web</div>
  <div class="sub">Analisis segun OWASP Top 10</div>
  <div class="meta">
    <div><strong>Objetivo:</strong> {{ meta.nombre }}</div>
    <div><strong>URL:</strong> {{ meta.objetivo }}</div>
    <div><strong>Fecha:</strong> {{ fecha_legible }}</div>
    <div><strong>Duracion del analisis:</strong> {{ meta.duracion_segundos }} segundos</div>
    <div><strong>Total de hallazgos:</strong> {{ meta.total_hallazgos }}</div>
  </div>
</div>

<!-- ===================== RESUMEN EJECUTIVO ===================== -->
<h1>1. Resumen Ejecutivo</h1>

{% if valoracion %}
<div class="valoracion" style="background: {{ color_nivel_global }};">
  <div class="puntuacion">{{ valoracion.puntuacion }}/10</div>
  <div class="nivel">Riesgo {{ valoracion.nivel }}</div>
</div>
<p>{{ valoracion.descripcion }}</p>
{% endif %}

<h3>Distribucion de hallazgos por severidad</h3>
<table>
  <tr><th>Severidad</th><th>Cantidad</th><th>Representacion</th></tr>
  {% for sev, cant in resumen_sev.items() %}
  <tr>
    <td><span class="badge" style="background: {{ colores_sev[sev] }};">{{ sev|capitalize }}</span></td>
    <td>{{ cant }}</td>
    <td>
      <div class="barra-cont">
        {% if cant > 0 %}
        <div class="barra" style="background: {{ colores_sev[sev] }}; width: {{ (cant / max_sev * 100)|round|int }}%;">{{ cant }}</div>
        {% endif %}
      </div>
    </td>
  </tr>
  {% endfor %}
</table>

<!-- ===================== MATRIZ DE RIESGO ===================== -->
{% if matriz %}
<h1>2. Matriz de Riesgo</h1>
<p>Cada hallazgo se ubica segun su <strong>impacto</strong> (eje vertical) y su
<strong>probabilidad de explotacion</strong> (eje horizontal). El numero en cada
celda indica cuantos hallazgos caen en ese nivel de riesgo.</p>

<table class="matriz">
  <tr>
    <th class="eje">I \ P</th>
    <th class="eje">1</th><th class="eje">2</th><th class="eje">3</th>
    <th class="eje">4</th><th class="eje">5</th>
  </tr>
  {% for fila in matriz.celdas %}
  <tr>
    <th class="eje">{{ fila[0].impacto }}</th>
    {% for celda in fila %}
    <td class="celda" style="background: {{ colores_nivel[celda.nivel] }};">
      <div class="n">{{ celda.cantidad if celda.cantidad > 0 else '' }}</div>
    </td>
    {% endfor %}
  </tr>
  {% endfor %}
</table>
<p style="text-align:center; font-size:11px; color:#546E7A;">
  Eje vertical (I): Impacto 1-5 &nbsp;|&nbsp; Eje horizontal (P): Probabilidad 1-5
</p>
{% endif %}

<!-- ===================== HALLAZGOS ===================== -->
<h1>3. Hallazgos Detallados</h1>
<p>Los hallazgos se agrupan por categoria OWASP Top 10 y se ordenan por severidad.</p>

{% for categoria, lista in hallazgos_por_categoria.items() %}
<div class="categoria-seccion">
<h2>{{ categoria }}</h2>
{% for h in lista %}
<div class="hallazgo" style="border-left-color: {{ colores_sev[h.severidad] }};">
  <h4>{{ h.titulo }}</h4>
  <div class="campo">
    <span class="badge" style="background: {{ colores_sev[h.severidad] }};">{{ h.severidad|capitalize }}</span>
    {% if h.cvss %}<span class="etiqueta">CVSS:</span> {{ h.cvss }}{% endif %}
    <span class="etiqueta">| Fuente:</span> {{ h.herramienta_origen }}
  </div>
  <div class="campo">{{ h.descripcion }}</div>
  {% if h.url_afectada %}
  <div class="campo"><span class="etiqueta">Ubicacion:</span> {{ h.url_afectada }}</div>
  {% endif %}
  {% if h.evidencia %}
  <div class="campo"><span class="etiqueta">Evidencia:</span>
    <div class="evidencia">{{ h.evidencia }}</div>
  </div>
  {% endif %}
  {% if h.recomendacion %}
  <div class="campo"><span class="etiqueta">Recomendacion:</span> {{ h.recomendacion }}</div>
  {% endif %}
</div>
{% endfor %}
</div>
{% endfor %}

<div class="footer-nota">
  Informe generado automaticamente por la herramienta de auditoria de seguridad web.
  Los resultados de herramientas automaticas deben ser validados manualmente por un
  auditor. La estimacion de probabilidad de la matriz de riesgo es una heuristica
  basada en la categoria OWASP y debe ajustarse al contexto real del objetivo.
</div>

</body>
</html>""")


def generar(datos: dict, carpeta: str, formatos: list, logger: logging.Logger) -> list:
    """
    Genera el informe en los formatos pedidos.

    datos    : dict de Reporte.construir() (metadatos, hallazgos, analisis_riesgo).
    carpeta  : donde guardar los archivos.
    formatos : lista con 'html' y/o 'pdf'.
    Devuelve la lista de rutas de archivos generados.
    """
    os.makedirs(carpeta, exist_ok=True)
    generados = []

    # --- Preparar los datos para la plantilla ---
    contexto = _preparar_contexto(datos)
    html = PLANTILLA.render(**contexto)

    marca = datetime.now().strftime("%Y-%m-%d_%H%M%S")

    # --- HTML ---
    if "html" in formatos:
        ruta_html = os.path.join(carpeta, f"informe_{marca}.html")
        with open(ruta_html, "w", encoding="utf-8") as f:
            f.write(html)
        generados.append(ruta_html)
        logger.info(f"[reporte] Informe HTML generado: {ruta_html}")

    # --- PDF ---
    if "pdf" in formatos:
        try:
            from weasyprint import HTML
            ruta_pdf = os.path.join(carpeta, f"informe_{marca}.pdf")
            HTML(string=html).write_pdf(ruta_pdf)
            generados.append(ruta_pdf)
            logger.info(f"[reporte] Informe PDF generado: {ruta_pdf}")
        except Exception as e:
            logger.error(
                f"[reporte] No se pudo generar el PDF ({e}). "
                f"El HTML si se genero; puedes convertirlo a PDF desde el "
                f"navegador (Imprimir > Guardar como PDF)."
            )

    return generados


def _preparar_contexto(datos: dict) -> dict:
    """Transforma el dict del reporte en el contexto que espera la plantilla."""
    meta = datos.get("metadatos", {})
    resumen_sev = datos.get("resumen_por_severidad", {})
    hallazgos = datos.get("hallazgos", [])
    analisis = datos.get("analisis_riesgo", {})

    valoracion = analisis.get("valoracion_global") if analisis else None
    matriz = analisis.get("matriz") if analisis else None

    # Color del recuadro de valoracion global.
    color_nivel_global = "#607D8B"
    if valoracion:
        color_nivel_global = COLOR_NIVEL.get(valoracion.get("nivel"), "#607D8B")

    # Para escalar las barras del grafico de severidad.
    max_sev = max(resumen_sev.values()) if resumen_sev and any(resumen_sev.values()) else 1

    # Agrupar hallazgos por categoria OWASP (ya vienen ordenados por severidad).
    hallazgos_por_categoria = {}
    for h in hallazgos:
        cat = h.get("categoria", "Sin categoria")
        hallazgos_por_categoria.setdefault(cat, []).append(h)

    # Fecha legible.
    fecha_legible = meta.get("fecha_inicio", "")
    try:
        fecha_legible = datetime.fromisoformat(fecha_legible).strftime(
            "%d/%m/%Y %H:%M"
        )
    except (ValueError, TypeError):
        pass

    return {
        "meta": meta,
        "fecha_legible": fecha_legible,
        "resumen_sev": resumen_sev,
        "max_sev": max_sev,
        "colores_sev": COLOR_SEVERIDAD,
        "colores_nivel": COLOR_NIVEL,
        "valoracion": valoracion,
        "color_nivel_global": color_nivel_global,
        "matriz": matriz,
        "hallazgos_por_categoria": hallazgos_por_categoria,
    }


# Prueba independiente:
#     python3 -m core.reporte_html
# Genera un informe de ejemplo con datos ficticios.
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    log = logging.getLogger("prueba")

    # Datos de ejemplo simulando la salida de Reporte.construir() + riesgo.
    datos_ejemplo = {
        "metadatos": {
            "objetivo": "https://ejemplo.local",
            "nombre": "Sitio de prueba",
            "fecha_inicio": datetime.now().isoformat(),
            "fecha_fin": datetime.now().isoformat(),
            "duracion_segundos": 123.4,
            "total_hallazgos": 3,
        },
        "resumen_por_severidad": {
            "critica": 1, "alta": 0, "media": 1, "baja": 1, "informativa": 0
        },
        "hallazgos": [
            {"titulo": "Inyeccion SQL en login", "categoria": "A03:2021 - Injection",
             "severidad": "critica", "cvss": 9.8, "descripcion": "SQLi detectada.",
             "evidencia": "id=1 AND 1=1", "recomendacion": "Usar consultas parametrizadas.",
             "herramienta_origen": "modulo_sqlmap", "url_afectada": "https://ejemplo.local/login"},
            {"titulo": "Falta CSP", "categoria": "A05:2021 - Security Misconfiguration",
             "severidad": "media", "cvss": 5.3, "descripcion": "Sin Content-Security-Policy.",
             "evidencia": "Sin cabecera CSP", "recomendacion": "Añadir CSP.",
             "herramienta_origen": "modulo_cabeceras_http", "url_afectada": "https://ejemplo.local/"},
            {"titulo": "Cookie sin HttpOnly", "categoria": "A02:2021 - Cryptographic Failures",
             "severidad": "baja", "cvss": 3.1, "descripcion": "Cookie insegura.",
             "evidencia": "sessionid sin HttpOnly", "recomendacion": "Añadir HttpOnly.",
             "herramienta_origen": "modulo_cookies", "url_afectada": "https://ejemplo.local/"},
        ],
        "analisis_riesgo": {
            "valoracion_global": {
                "puntuacion": 8.6, "nivel": "Alto",
                "descripcion": "El objetivo presenta un nivel de riesgo ALTO con 1 hallazgo critico."
            },
            "matriz": {
                "celdas": [
                    [{"impacto": 5, "probabilidad": p, "valor": 5*p,
                      "nivel": "Critico" if 5*p>=20 else "Alto" if 5*p>=12 else "Medio" if 5*p>=6 else "Bajo",
                      "cantidad": 1 if p==5 else 0, "hallazgos": []} for p in range(1,6)],
                    [{"impacto": 4, "probabilidad": p, "valor": 4*p,
                      "nivel": "Critico" if 4*p>=20 else "Alto" if 4*p>=12 else "Medio" if 4*p>=6 else "Bajo",
                      "cantidad": 0, "hallazgos": []} for p in range(1,6)],
                    [{"impacto": 3, "probabilidad": p, "valor": 3*p,
                      "nivel": "Alto" if 3*p>=12 else "Medio" if 3*p>=6 else "Bajo",
                      "cantidad": 1 if p==4 else 0, "hallazgos": []} for p in range(1,6)],
                    [{"impacto": 2, "probabilidad": p, "valor": 2*p,
                      "nivel": "Medio" if 2*p>=6 else "Bajo",
                      "cantidad": 1 if p==3 else 0, "hallazgos": []} for p in range(1,6)],
                    [{"impacto": 1, "probabilidad": p, "valor": 1*p,
                      "nivel": "Bajo", "cantidad": 0, "hallazgos": []} for p in range(1,6)],
                ]
            }
        }
    }

    print("Generando informe de ejemplo (HTML y PDF)...\n")
    rutas = generar(datos_ejemplo, "informe_prueba", ["html", "pdf"], log)
    print(f"\nArchivos generados:")
    for r in rutas:
        print(f"  {r}")