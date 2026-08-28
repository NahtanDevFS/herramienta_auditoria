"""
riesgo.py — Motor de analisis de riesgos.
Toma la lista de hallazgos y produce: normalizacion de CVSS, matriz de
riesgo (probabilidad x impacto) y metricas agregadas.
"""

from core.modelo_hallazgo import Hallazgo, Severidad


CVSS_POR_SEVERIDAD = {
    Severidad.CRITICA: 9.5,
    Severidad.ALTA: 7.5,
    Severidad.MEDIA: 5.0,
    Severidad.BAJA: 2.5,
    Severidad.INFORMATIVA: 0.0,
}

IMPACTO_POR_SEVERIDAD = {
    Severidad.CRITICA: 5,
    Severidad.ALTA: 4,
    Severidad.MEDIA: 3,
    Severidad.BAJA: 2,
    Severidad.INFORMATIVA: 1,
}

# Probabilidad de explotacion tipica por categoria OWASP Top 10:2025 (1-5).
PROBABILIDAD_POR_CATEGORIA = {
    "A01": 4,  # Broken Access Control (incluye SSRF)
    "A02": 4,  # Security Misconfiguration
    "A03": 4,  # Software Supply Chain Failures
    "A04": 2,  # Cryptographic Failures
    "A05": 5,  # Injection
    "A06": 2,  # Insecure Design
    "A07": 3,  # Authentication Failures
    "A08": 2,  # Software or Data Integrity Failures
    "A09": 1,  # Security Logging and Alerting Failures
    "A10": 3,  # Mishandling of Exceptional Conditions
}


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
    def __init__(self, hallazgos: list[Hallazgo]):
        self.hallazgos = hallazgos

    def analizar(self) -> dict:
        riesgos = [h for h in self.hallazgos if h.severidad != Severidad.INFORMATIVA]
        return {
            "resumen": self._resumen(riesgos),
            "matriz": self._matriz(riesgos),
            "hallazgos_evaluados": self._evaluar_hallazgos(riesgos),
            "valoracion_global": self._valoracion_global(riesgos),
        }

    def _cvss_efectivo(self, h: Hallazgo) -> float:
        if h.cvss is not None:
            return h.cvss
        return CVSS_POR_SEVERIDAD.get(h.severidad, 0.0)

    def _evaluar_hallazgos(self, riesgos: list[Hallazgo]) -> list[dict]:
        evaluados = []
        for h in riesgos:
            impacto = IMPACTO_POR_SEVERIDAD.get(h.severidad, 1)
            clave_cat = h.categoria.name
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

        evaluados.sort(key=lambda e: e["puntuacion_riesgo"], reverse=True)
        return evaluados

    def _matriz(self, riesgos: list[Hallazgo]) -> dict:
        celdas = {i: {p: [] for p in range(1, 6)} for i in range(1, 6)}

        for h in riesgos:
            impacto = IMPACTO_POR_SEVERIDAD.get(h.severidad, 1)
            probabilidad = PROBABILIDAD_POR_CATEGORIA.get(h.categoria.name, 3)
            celdas[impacto][probabilidad].append(h.titulo)

        matriz_repr = []
        for impacto in range(5, 0, -1):
            fila = []
            for probabilidad in range(1, 6):
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
        if not riesgos:
            return {
                "puntuacion": 0.0,
                "nivel": "Bajo",
                "descripcion": "No se identificaron riesgos significativos.",
            }

        cvss_valores = [self._cvss_efectivo(h) for h in riesgos]
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