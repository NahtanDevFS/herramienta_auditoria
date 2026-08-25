"""
riesgo.py  (motor de analisis de riesgos - Fase 5)
Toma la lista de hallazgos de la auditoria y produce el ANALISIS DE RIESGOS,
que es uno de los objetivos formales del proyecto. Hace tres cosas:

  1. Normaliza el CVSS: si un hallazgo no trae CVSS, le asigna uno estimado a
     partir de su severidad, para que todos sean comparables.

  2. Construye la MATRIZ DE RIESGO (probabilidad x impacto), la representacion
     clasica de un analisis de riesgos. Cada hallazgo se ubica en una celda
     segun su probabilidad de explotacion y su impacto.

  3. Calcula METRICAS AGREGADAS: puntuacion global de riesgo del objetivo,
     conteos por nivel, y una valoracion general (bajo/medio/alto/critico).

Este modulo NO detecta nada: solo analiza los hallazgos que ya existen. Por eso
vive en 'core/' (logica central) y no en 'modulos/' (detectores).
"""

from core.modelo_hallazgo import Hallazgo, Severidad


# CVSS estimado por severidad, para hallazgos que no traigan uno propio.
# Son valores representativos del punto medio de cada banda CVSS 3.1.
CVSS_POR_SEVERIDAD = {
    Severidad.CRITICA: 9.5,
    Severidad.ALTA: 7.5,
    Severidad.MEDIA: 5.0,
    Severidad.BAJA: 2.5,
    Severidad.INFORMATIVA: 0.0,
}

# Para la matriz probabilidad x impacto necesitamos dos ejes:
#
#   IMPACTO: lo derivamos de la severidad del hallazgo (que ya pondera el daño
#            potencial). Escala 1-5.
#
#   PROBABILIDAD: la estimamos segun la categoria OWASP y la facilidad de
#                 explotacion tipica de ese tipo de fallo. Escala 1-5.
#
# La multiplicacion (impacto x probabilidad) da el nivel de riesgo, de 1 a 25.

IMPACTO_POR_SEVERIDAD = {
    Severidad.CRITICA: 5,
    Severidad.ALTA: 4,
    Severidad.MEDIA: 3,
    Severidad.BAJA: 2,
    Severidad.INFORMATIVA: 1,
}

# Probabilidad de explotacion tipica por categoria OWASP (1=raro, 5=muy comun).
# Se basa en lo explotables y frecuentes que suelen ser estos fallos.
PROBABILIDAD_POR_CATEGORIA = {
    "A01": 4,  # Broken Access Control: comun y explotable
    "A02": 3,  # Cryptographic Failures: requiere posicion de red a veces
    "A03": 5,  # Injection: muy explotable, herramientas automaticas
    "A04": 2,  # Insecure Design: dificil de explotar directamente
    "A05": 4,  # Security Misconfiguration: muy comun
    "A06": 4,  # Vulnerable Components: exploits publicos disponibles
    "A07": 3,  # Auth Failures: depende de la configuracion
    "A08": 2,  # Data Integrity: mas dificil de explotar
    "A09": 1,  # Logging Failures: no explotable directamente
    "A10": 3,  # SSRF: explotable pero requiere condiciones
}

# Niveles de riesgo segun el producto impacto x probabilidad (1-25).
def _nivel_riesgo(valor: int) -> str:
    if valor >= 20:
        return "Critico"
    if valor >= 12:
        return "Alto"
    if valor >= 6:
        return "Medio"
    if valor >= 1:
        return "Bajo"
    return "Informativo"


class MotorRiesgo:
    """
    Analiza una lista de hallazgos y produce el analisis de riesgos completo.

    Uso:
        motor = MotorRiesgo(lista_de_hallazgos)
        analisis = motor.analizar()   # devuelve un dict con todo el analisis
    """

    def __init__(self, hallazgos: list[Hallazgo]):
        self.hallazgos = hallazgos

    def analizar(self) -> dict:
        """Ejecuta todo el analisis y devuelve un diccionario con los resultados."""
        # Excluimos los informativos del calculo de riesgo (no son riesgos).
        riesgos = [h for h in self.hallazgos
                   if h.severidad != Severidad.INFORMATIVA]

        return {
            "resumen": self._resumen(riesgos),
            "matriz": self._matriz(riesgos),
            "hallazgos_evaluados": self._evaluar_hallazgos(riesgos),
            "valoracion_global": self._valoracion_global(riesgos),
        }

    def _cvss_efectivo(self, h: Hallazgo) -> float:
        """Devuelve el CVSS del hallazgo, o uno estimado por su severidad."""
        if h.cvss is not None:
            return h.cvss
        return CVSS_POR_SEVERIDAD.get(h.severidad, 0.0)

    def _evaluar_hallazgos(self, riesgos: list[Hallazgo]) -> list[dict]:
        """
        Calcula para cada hallazgo su impacto, probabilidad, puntuacion de
        riesgo y nivel. Devuelve una lista ordenada de mayor a menor riesgo.
        """
        evaluados = []
        for h in riesgos:
            impacto = IMPACTO_POR_SEVERIDAD.get(h.severidad, 1)
            # La clave de categoria es tipo "A03"; la extraemos del value.
            clave_cat = h.categoria.name  # 'A03'
            probabilidad = PROBABILIDAD_POR_CATEGORIA.get(clave_cat, 3)
            puntuacion = impacto * probabilidad

            evaluados.append({
                "id": h.id,
                "titulo": h.titulo,
                "categoria": clave_cat,
                "severidad": h.severidad.value,
                "cvss": self._cvss_efectivo(h),
                "impacto": impacto,
                "probabilidad": probabilidad,
                "puntuacion_riesgo": puntuacion,
                "nivel_riesgo": _nivel_riesgo(puntuacion),
            })

        # Ordenar de mayor a menor riesgo.
        evaluados.sort(key=lambda e: e["puntuacion_riesgo"], reverse=True)
        return evaluados

    def _matriz(self, riesgos: list[Hallazgo]) -> dict:
        """
        Construye la matriz probabilidad x impacto (5x5).
        Devuelve una estructura con el conteo de hallazgos en cada celda,
        lista para representarse en el reporte.

        Filas = impacto (5 arriba, 1 abajo).
        Columnas = probabilidad (1 izquierda, 5 derecha).
        """
        # Inicializar matriz 5x5 con listas vacias.
        # celdas[impacto][probabilidad] = lista de titulos de hallazgos
        celdas = {i: {p: [] for p in range(1, 6)} for i in range(1, 6)}

        for h in riesgos:
            impacto = IMPACTO_POR_SEVERIDAD.get(h.severidad, 1)
            probabilidad = PROBABILIDAD_POR_CATEGORIA.get(h.categoria.name, 3)
            celdas[impacto][probabilidad].append(h.titulo)

        # Construir una representacion con conteos y nivel de cada celda.
        matriz_repr = []
        for impacto in range(5, 0, -1):  # de 5 (arriba) a 1 (abajo)
            fila = []
            for probabilidad in range(1, 6):  # de 1 a 5
                titulos = celdas[impacto][probabilidad]
                valor = impacto * probabilidad
                fila.append({
                    "impacto": impacto,
                    "probabilidad": probabilidad,
                    "valor": valor,
                    "nivel": _nivel_riesgo(valor),
                    "cantidad": len(titulos),
                    "hallazgos": titulos,
                })
            matriz_repr.append(fila)

        return {
            "celdas": matriz_repr,
            "leyenda": {
                "eje_x": "Probabilidad (1=raro, 5=muy probable)",
                "eje_y": "Impacto (1=minimo, 5=maximo)",
            },
        }

    def _resumen(self, riesgos: list[Hallazgo]) -> dict:
        """Conteos por severidad y por nivel de riesgo."""
        por_severidad = {sev.value: 0 for sev in Severidad}
        for h in self.hallazgos:
            por_severidad[h.severidad.value] += 1

        por_nivel = {"Critico": 0, "Alto": 0, "Medio": 0, "Bajo": 0}
        for h in riesgos:
            impacto = IMPACTO_POR_SEVERIDAD.get(h.severidad, 1)
            probabilidad = PROBABILIDAD_POR_CATEGORIA.get(h.categoria.name, 3)
            nivel = _nivel_riesgo(impacto * probabilidad)
            if nivel in por_nivel:
                por_nivel[nivel] += 1

        return {
            "total_hallazgos": len(self.hallazgos),
            "total_riesgos": len(riesgos),
            "por_severidad": por_severidad,
            "por_nivel_riesgo": por_nivel,
        }

    def _valoracion_global(self, riesgos: list[Hallazgo]) -> dict:
        """
        Calcula una puntuacion global de riesgo del objetivo y una valoracion
        cualitativa. Usa el CVSS efectivo de los hallazgos.
        """
        if not riesgos:
            return {
                "puntuacion": 0.0,
                "nivel": "Bajo",
                "descripcion": (
                    "No se identificaron riesgos significativos "
                    "(solo hallazgos informativos, si los hay)."
                ),
            }

        cvss_valores = [self._cvss_efectivo(h) for h in riesgos]
        # La puntuacion global pondera el peor caso y la media, para que un
        # unico hallazgo critico pese, pero tambien cuente el volumen.
        cvss_max = max(cvss_valores)
        cvss_medio = sum(cvss_valores) / len(cvss_valores)
        puntuacion = round(0.6 * cvss_max + 0.4 * cvss_medio, 1)

        if puntuacion >= 9.0:
            nivel = "Critico"
        elif puntuacion >= 7.0:
            nivel = "Alto"
        elif puntuacion >= 4.0:
            nivel = "Medio"
        else:
            nivel = "Bajo"

        # Contar criticos y altos para la descripcion.
        n_criticos = sum(1 for h in riesgos if h.severidad == Severidad.CRITICA)
        n_altos = sum(1 for h in riesgos if h.severidad == Severidad.ALTA)

        descripcion = (
            f"El objetivo presenta un nivel de riesgo {nivel.upper()}. Se "
            f"identificaron {len(riesgos)} riesgo(s), de los cuales "
            f"{n_criticos} son criticos y {n_altos} son altos."
        )

        return {
            "puntuacion": puntuacion,
            "nivel": nivel,
            "cvss_maximo": round(cvss_max, 1),
            "cvss_medio": round(cvss_medio, 1),
            "descripcion": descripcion,
        }


# Prueba independiente:
#     python3 -m core.riesgo
if __name__ == "__main__":
    from core.modelo_hallazgo import Hallazgo

    print("Probando el motor de riesgo...\n")

    hallazgos = [
        Hallazgo(titulo="Inyeccion SQL en login", categoria="A03",
                 severidad="critica", descripcion="SQLi", cvss=9.8),
        Hallazgo(titulo="Falta CSP", categoria="A05",
                 severidad="media", descripcion="Sin CSP", cvss=5.3),
        Hallazgo(titulo="Cookie sin HttpOnly", categoria="A02",
                 severidad="baja", descripcion="Cookie", cvss=3.1),
        Hallazgo(titulo="MongoDB expuesto", categoria="A05",
                 severidad="critica", descripcion="DB expuesta", cvss=9.1),
        Hallazgo(titulo="Inventario de tecnologias", categoria="A06",
                 severidad="informativa", descripcion="Info"),  # sin cvss
    ]

    motor = MotorRiesgo(hallazgos)
    analisis = motor.analizar()

    print("=== VALORACION GLOBAL ===")
    vg = analisis["valoracion_global"]
    print(f"  Puntuacion: {vg['puntuacion']} | Nivel: {vg['nivel']}")
    print(f"  {vg['descripcion']}")

    print("\n=== RESUMEN ===")
    r = analisis["resumen"]
    print(f"  Total hallazgos: {r['total_hallazgos']} (riesgos: {r['total_riesgos']})")
    print(f"  Por nivel de riesgo: {r['por_nivel_riesgo']}")

    print("\n=== HALLAZGOS EVALUADOS (orden de riesgo) ===")
    for e in analisis["hallazgos_evaluados"]:
        print(f"  [{e['nivel_riesgo']:8}] {e['titulo']:35} "
              f"I={e['impacto']} x P={e['probabilidad']} = {e['puntuacion_riesgo']}")

    print("\n=== MATRIZ DE RIESGO (impacto vertical, probabilidad horizontal) ===")
    print("        P1    P2    P3    P4    P5")
    for fila in analisis["matriz"]["celdas"]:
        impacto = fila[0]["impacto"]
        celdas_txt = "  ".join(f"{c['cantidad']:3d}[{c['valor']:2d}]" for c in fila)
        print(f"  I{impacto}   {celdas_txt}")