# consolida hallazgos y genera un reporte JSON con metadatos y resumen

import json
import os
from datetime import datetime

# importa clases del modelo interno. para prueba unitaria, ver bloque __main__ al final.
from core.modelo_hallazgo import Hallazgo, Severidad


# orden de severidad para priorizar hallazgos en el reporte (lo critico primero)
ORDEN_SEVERIDAD = {
    Severidad.CRITICA: 0,
    Severidad.ALTA: 1,
    Severidad.MEDIA: 2,
    Severidad.BAJA: 3,
    Severidad.INFORMATIVA: 4,
}


class Reporte:
    # acumula hallazgos durante la auditoria y los exporta al final

    def __init__(self, objetivo: str, nombre: str = ""):
        # objetivo: URL de la web auditada. nombre: descriptivo para el reporte.
        self.objetivo = objetivo
        self.nombre = nombre
        self.hallazgos: list[Hallazgo] = []
        self.inicio = datetime.now()
        self.fin: datetime | None = None
        self.analisis_riesgo = None
        self.resumen_agente = None

    def set_analisis_riesgo(self, analisis: dict) -> None:
        # guarda el analisis de riesgos (de la fase 5) para incluirlo en el reporte
        self.analisis_riesgo = analisis

    def set_resumen_agente(self, resumen: dict) -> None:
        # guarda el resumen de cierre del agente de IA (bitacora + narrativa)
        self.resumen_agente = resumen

    def agregar(self, hallazgo: Hallazgo) -> None:
        # añade un unico hallazgo al reporte
        if not isinstance(hallazgo, Hallazgo):
            raise TypeError(
                f"Se esperaba un objeto Hallazgo, se recibio: {type(hallazgo)}"
            )
        self.hallazgos.append(hallazgo)

    def agregar_varios(self, hallazgos: list[Hallazgo]) -> None:
        # añade una lista de hallazgos de golpe (lo que devuelve un modulo)
        for h in hallazgos:
            self.agregar(h)

    def finalizar(self) -> None:
        # marca el fin de la auditoria (para calcular la duracion)
        self.fin = datetime.now()

    def _resumen_por_severidad(self) -> dict:
        # conteo de hallazgos por severidad. inicializa todas en 0 para que aparezcan siempre.
        conteo = {sev.value: 0 for sev in Severidad}
        for h in self.hallazgos:
            conteo[h.severidad.value] += 1
        return conteo

    def _hallazgos_ordenados(self) -> list[Hallazgo]:
        # devuelve los hallazgos ordenados de mas grave a menos grave
        return sorted(
            self.hallazgos,
            key=lambda h: ORDEN_SEVERIDAD[h.severidad],
        )

    def construir(self) -> dict:
        # arma diccionario del reporte. llama a finalizar() si falta para tener duracion.
        if self.fin is None:
            self.finalizar()

        duracion_seg = (self.fin - self.inicio).total_seconds()

        datos = {
            "metadatos": {
                "objetivo": self.objetivo,
                "nombre": self.nombre,
                "fecha_inicio": self.inicio.isoformat(),
                "fecha_fin": self.fin.isoformat(),
                "duracion_segundos": round(duracion_seg, 2),
                "total_hallazgos": len(self.hallazgos),
            },
            "resumen_por_severidad": self._resumen_por_severidad(),
            "hallazgos": [h.to_dict() for h in self._hallazgos_ordenados()],
        }

        # añadir el analisis de riesgo si existe (fase 5)
        if self.analisis_riesgo:
            datos["analisis_riesgo"] = self.analisis_riesgo

        # añadir el resumen de cierre del agente de IA si existe
        if self.resumen_agente:
            datos["resumen_agente"] = self.resumen_agente

        return datos

    def guardar_json(self, carpeta: str = "resultados") -> str:
        # guarda reporte JSON en carpeta (la crea si no existe) con fecha/hora en nombre.
        os.makedirs(carpeta, exist_ok=True)

        # nombre unico basado en la fecha: reporte_2026 07 16_0130 JSON
        marca = self.inicio.strftime("%Y-%m-%d_%H%M%S")
        nombre_archivo = f"reporte_{marca}.json"
        ruta = os.path.join(carpeta, nombre_archivo)

        datos = self.construir()

        # ensure_ascii=false mantiene tildes; indent=2 para formato legible
        with open(ruta, "w", encoding="utf-8") as f:
            json.dump(datos, f, ensure_ascii=False, indent=2)

        return ruta

    def imprimir_resumen(self) -> None:
        # muestra un resumen rapido por consola al terminar la auditoria
        datos = self.construir()
        meta = datos["metadatos"]
        resumen = datos["resumen_por_severidad"]

        print("\n" + "=" * 55)
        print("  RESUMEN DE LA AUDITORIA")
        print("=" * 55)
        print(f"  Objetivo : {meta['objetivo']}")
        print(f"  Duracion : {meta['duracion_segundos']} s")
        print(f"  Total    : {meta['total_hallazgos']} hallazgos")
        print("-" * 55)
        for severidad, cantidad in resumen.items():
            print(f"  {severidad.capitalize():14} : {cantidad}")
        print("=" * 55)


# bloque de prueba unitaria: crea hallazgos de ejemplo, genera y guarda reporte
if __name__ == "__main__":
    print("Probando el modulo de reporte...\n")

    rep = Reporte(
        objetivo="http://objetivo.local",
        nombre="Prueba de reporte",
    )

    # hallazgos de prueba desordenados para verificar que el reporte los ordena
    rep.agregar(Hallazgo(
        titulo="Cabecera CSP ausente",
        categoria="A02",
        severidad="media",
        descripcion="No se envia Content-Security-Policy.",
        cvss=5.3,
    ))
    rep.agregar(Hallazgo(
        titulo="SQL Injection en formulario de login",
        categoria="A05",
        severidad="critica",
        descripcion="El parametro 'usuario' es vulnerable a inyeccion SQL.",
        cvss=9.8,
    ))
    rep.agregar(Hallazgo(
        titulo="Cookie sin flag HttpOnly",
        categoria="A04",
        severidad="baja",
        descripcion="La cookie de sesion no tiene el flag HttpOnly.",
        cvss=3.1,
    ))

    rep.finalizar()
    rep.imprimir_resumen()

    ruta = rep.guardar_json("resultados_prueba")
    print(f"\nReporte guardado en: {ruta}")
    print("Abrelo para ver la estructura del JSON generado.")