# Generador de reporte en Excel (.xlsx) a partir del mismo dict del reporte.
# Se llama con: generar_excel(datos, carpeta, logger) -> ruta del archivo.
# Hojas: Resumen, Hallazgos, Matriz de riesgo y Cierre del agente (si existe).

import logging
import os
from datetime import datetime

from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

NAVY = "1A237E"
GRIS_HDR = "E8EAF6"
BLANCO = "FFFFFF"

COLOR_SEVERIDAD = {
    "critica": "8B0000",
    "alta": "D32F2F",
    "media": "F57C00",
    "baja": "FBC02D",
    "informativa": "0288D1",
}
COLOR_NIVEL = {
    "Critico": "8B0000", "Alto": "D32F2F", "Medio": "F57C00",
    "Bajo": "FBC02D", "Informativo": "90A4AE",
}

_BORDE = Border(*[Side(style="thin", color="CFD8DC")] * 4)
_WRAP = Alignment(vertical="top", wrap_text=True)
_CENTER = Alignment(horizontal="center", vertical="center")


def _titulo(ws, texto):
    c = ws.cell(row=ws.max_row + 1, column=1, value=texto)
    c.font = Font(bold=True, size=14, color=NAVY)
    ws.append([])


def _fila_encabezado(ws, encabezados):
    fila = ws.max_row + 1
    for i, h in enumerate(encabezados, 1):
        c = ws.cell(row=fila, column=i, value=h)
        c.font = Font(bold=True, color=NAVY)
        c.fill = PatternFill("solid", fgColor=GRIS_HDR)
        c.border = _BORDE
        c.alignment = Alignment(vertical="center")
    return fila


def _hoja_resumen(wb, datos):
    ws = wb.active
    ws.title = "Resumen"
    meta = datos.get("metadatos", {})
    val = (datos.get("analisis_riesgo") or {}).get("valoracion_global", {})
    sev = datos.get("resumen_por_severidad", {})

    t = ws.cell(row=1, column=1, value="Informe de Auditoria de Seguridad Web")
    t.font = Font(bold=True, size=16, color=NAVY)
    ws.cell(row=2, column=1, value="Analisis segun OWASP Top 10").font = Font(
        italic=True, color="546E7A")
    ws.append([])

    datos_meta = [
        ("Objetivo", meta.get("nombre", "")),
        ("URL", meta.get("objetivo", "")),
        ("Fecha", meta.get("fecha_fin", meta.get("fecha_inicio", ""))),
        ("Duracion (s)", meta.get("duracion_segundos", "")),
        ("Total de hallazgos", meta.get("total_hallazgos", "")),
    ]
    if val:
        datos_meta += [
            ("Riesgo global", f"{val.get('puntuacion', '')}/10 "
                              f"({val.get('puntuacion_25', '')}/25)"),
            ("Nivel de riesgo", val.get("nivel", "")),
        ]
    for k, v in datos_meta:
        f = ws.max_row + 1
        ws.cell(row=f, column=1, value=k).font = Font(bold=True)
        ws.cell(row=f, column=2, value=v)

    ws.append([])
    _titulo(ws, "Hallazgos por severidad")
    _fila_encabezado(ws, ["Severidad", "Cantidad"])
    for clave in ("critica", "alta", "media", "baja", "informativa"):
        f = ws.max_row + 1
        c = ws.cell(row=f, column=1, value=clave.capitalize())
        c.fill = PatternFill("solid", fgColor=COLOR_SEVERIDAD[clave])
        c.font = Font(bold=True, color=BLANCO)
        c.border = _BORDE
        c2 = ws.cell(row=f, column=2, value=sev.get(clave, 0))
        c2.border = _BORDE

    ws.column_dimensions["A"].width = 22
    ws.column_dimensions["B"].width = 55


def _hoja_hallazgos(wb, datos):
    ws = wb.create_sheet("Hallazgos")
    encabezados = ["Severidad", "Categoria", "Titulo", "CVSS", "Fuente",
                   "URL afectada", "Descripcion", "Evidencia", "Recomendacion"]
    hdr = _fila_encabezado(ws, encabezados)
    ws.freeze_panes = f"A{hdr + 1}"

    for h in datos.get("hallazgos", []):
        f = ws.max_row + 1
        sev = (h.get("severidad") or "").lower()
        valores = [
            h.get("severidad", ""), h.get("categoria", ""), h.get("titulo", ""),
            h.get("cvss", ""), h.get("herramienta_origen", ""),
            h.get("url_afectada", ""), h.get("descripcion", ""),
            h.get("evidencia", ""), h.get("recomendacion", ""),
        ]
        for i, v in enumerate(valores, 1):
            c = ws.cell(row=f, column=i, value=v)
            c.border = _BORDE
            c.alignment = _WRAP
        # colorea la celda de severidad
        cs = ws.cell(row=f, column=1)
        if sev in COLOR_SEVERIDAD:
            cs.fill = PatternFill("solid", fgColor=COLOR_SEVERIDAD[sev])
            cs.font = Font(bold=True, color=BLANCO)
        cs.alignment = _CENTER

    anchos = [12, 34, 34, 7, 20, 32, 48, 48, 48]
    for i, w in enumerate(anchos, 1):
        ws.column_dimensions[get_column_letter(i)].width = w


def _hoja_matriz(wb, datos):
    matriz = (datos.get("analisis_riesgo") or {}).get("matriz")
    if not matriz or not matriz.get("celdas"):
        return
    ws = wb.create_sheet("Matriz de riesgo")
    ws.cell(row=1, column=1, value="Matriz de riesgo (Impacto x Probabilidad)").font = \
        Font(bold=True, size=13, color=NAVY)
    base = 3
    # encabezado de columnas (probabilidad 1..5)
    ws.cell(row=base, column=1, value="I \\ P").font = Font(bold=True, color=NAVY)
    for p in range(1, 6):
        c = ws.cell(row=base, column=1 + p, value=p)
        c.font = Font(bold=True, color=NAVY)
        c.fill = PatternFill("solid", fgColor=GRIS_HDR)
        c.alignment = _CENTER
        c.border = _BORDE
    # filas (impacto 5..1), con el conteo coloreado por nivel
    for ri, fila in enumerate(matriz["celdas"]):
        r = base + 1 + ri
        imp = fila[0].get("impacto") if fila else ""
        ce = ws.cell(row=r, column=1, value=imp)
        ce.font = Font(bold=True, color=NAVY)
        ce.fill = PatternFill("solid", fgColor=GRIS_HDR)
        ce.alignment = _CENTER
        ce.border = _BORDE
        for ci, celda in enumerate(fila):
            c = ws.cell(row=r, column=2 + ci,
                        value=(celda.get("cantidad") or ""))
            c.fill = PatternFill("solid",
                                 fgColor=COLOR_NIVEL.get(celda.get("nivel"), "FFFFFF"))
            c.font = Font(bold=True, color=BLANCO)
            c.alignment = _CENTER
            c.border = _BORDE
    ws.cell(row=base + 7, column=1,
            value="Eje vertical (I): Impacto 1-5  |  Eje horizontal (P): Probabilidad 1-5")
    for col in range(1, 7):
        ws.column_dimensions[get_column_letter(col)].width = 10


def _hoja_agente(wb, datos):
    ra = datos.get("resumen_agente")
    if not ra:
        return
    ws = wb.create_sheet("Cierre del agente")

    if ra.get("plan"):
        _titulo(ws, "Plan de la auditoria")
        for linea in str(ra["plan"]).splitlines():
            if linea.strip():
                ws.cell(row=ws.max_row + 1, column=1, value=linea.strip()).alignment = _WRAP
        ws.append([])

    if ra.get("checklist"):
        _titulo(ws, "Checklist de objetivos")
        _fila_encabezado(ws, ["Objetivo", "URL", "Estado"])
        for it in ra["checklist"]:
            f = ws.max_row + 1
            estado = {"hallazgo": "Con hallazgo", "probado": "Probado"}.get(
                it.get("estado"), "Pendiente")
            for i, v in enumerate([it.get("descripcion", ""), it.get("url", ""), estado], 1):
                c = ws.cell(row=f, column=i, value=v)
                c.border = _BORDE
                c.alignment = _WRAP
        ws.append([])

    if ra.get("narrativa"):
        _titulo(ws, "Valoracion del agente")
        for linea in str(ra["narrativa"]).splitlines():
            if linea.strip():
                ws.cell(row=ws.max_row + 1, column=1, value=linea.strip()).alignment = _WRAP
        ws.append([])

    if ra.get("acciones"):
        _titulo(ws, "Bitacora de acciones")
        _fila_encabezado(ws, ["#", "Accion", "Resultado"])
        for n, b in enumerate(ra["acciones"], 1):
            f = ws.max_row + 1
            for i, v in enumerate([n, b.get("accion", ""), b.get("resultado", "")], 1):
                c = ws.cell(row=f, column=i, value=v)
                c.border = _BORDE
                c.alignment = _WRAP

    ws.column_dimensions["A"].width = 40
    ws.column_dimensions["B"].width = 55
    ws.column_dimensions["C"].width = 55


def generar_excel(datos: dict, carpeta: str, logger: logging.Logger) -> str:
    # genera el .xlsx y devuelve su ruta
    os.makedirs(carpeta, exist_ok=True)
    wb = Workbook()
    _hoja_resumen(wb, datos)
    _hoja_hallazgos(wb, datos)
    _hoja_matriz(wb, datos)
    _hoja_agente(wb, datos)

    marca = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    ruta = os.path.join(carpeta, f"informe_{marca}.xlsx")
    wb.save(ruta)
    logger.info(f"[reporte] Informe Excel generado: {ruta}")
    return ruta


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    demo = {
        "metadatos": {"nombre": "Prueba", "objetivo": "http://x", "fecha_fin": "2026",
                      "duracion_segundos": 10, "total_hallazgos": 2},
        "resumen_por_severidad": {"critica": 1, "alta": 0, "media": 1, "baja": 0,
                                  "informativa": 0},
        "analisis_riesgo": {
            "valoracion_global": {"puntuacion": 8.1, "puntuacion_25": 20.2, "nivel": "Alto"},
            "matriz": {"celdas": [[{"impacto": i, "probabilidad": p, "cantidad": 0,
                                    "nivel": "Bajo"} for p in range(1, 6)]
                                  for i in range(5, 0, -1)]}},
        "hallazgos": [{"severidad": "critica", "categoria": "A05:2025 - Injection",
                       "titulo": "SQLi", "cvss": 9.8, "herramienta_origen": "agente_ia",
                       "url_afectada": "http://x/login", "descripcion": "d",
                       "evidencia": "e", "recomendacion": "r"}],
        "resumen_agente": {"plan": "Plan.", "checklist": [{"descripcion": "Login",
                           "url": "http://x", "estado": "hallazgo"}],
                           "narrativa": "Todo mal.", "acciones": [{"accion": "a", "resultado": "r"}]},
    }
    print(generar_excel(demo, "resultados_prueba", logging.getLogger("x")))
