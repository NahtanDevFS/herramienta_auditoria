"""
reporte.py
Consolida todos los hallazgos de la auditoria y los guarda en disco.

En esta fase (Fase 1) genera un reporte en formato JSON. Ese JSON contiene:
  - Metadatos de la auditoria (objetivo, fecha, duracion).
  - Un resumen con el conteo de hallazgos por severidad.
  - La lista completa de hallazgos.

Mas adelante (Fase 6) añadiremos a este mismo modulo la generacion de
reportes en HTML y PDF, reutilizando la estructura que armamos aqui.
"""

import json
import os
from datetime import datetime

# Importamos las clases del modelo. El punto (.) indica "del mismo paquete core".
# Si ejecutas este archivo directamente, mira el bloque __main__ al final.
from core.modelo_hallazgo import Hallazgo, Severidad


# Orden de severidad de mas grave a menos grave.
# Sirve para ordenar los hallazgos en el reporte: primero lo critico.
ORDEN_SEVERIDAD = {
    Severidad.CRITICA: 0,
    Severidad.ALTA: 1,
    Severidad.MEDIA: 2,
    Severidad.BAJA: 3,
    Severidad.INFORMATIVA: 4,
}


class Reporte:
    """
    Acumula hallazgos durante la auditoria y los exporta al final.

    Uso tipico:
        rep = Reporte(objetivo="http://web.local", nombre="Web de prueba")
        rep.agregar(un_hallazgo)
        rep.agregar_varios(lista_de_hallazgos)
        rep.finalizar()
        ruta = rep.guardar_json("resultados")
    """

    def __init__(self, objetivo: str, nombre: str = ""):
        """
        objetivo : URL de la web auditada.
        nombre   : Nombre descriptivo del objetivo (para el reporte).
        """
        self.objetivo = objetivo
        self.nombre = nombre
        self.hallazgos: list[Hallazgo] = []
        self.inicio = datetime.now()
        self.fin: datetime | None = None
        self.analisis_riesgo = None
    
    def set_analisis_riesgo(self, analisis: dict) -> None:
        """Guarda el analisis de riesgos (de la Fase 5) para incluirlo en el reporte."""
        self.analisis_riesgo = analisis

    def agregar(self, hallazgo: Hallazgo) -> None:
        """Añade un unico hallazgo al reporte."""
        if not isinstance(hallazgo, Hallazgo):
            raise TypeError(
                f"Se esperaba un objeto Hallazgo, se recibio: {type(hallazgo)}"
            )
        self.hallazgos.append(hallazgo)

    def agregar_varios(self, hallazgos: list[Hallazgo]) -> None:
        """Añade una lista de hallazgos de golpe (lo que devuelve un modulo)."""
        for h in hallazgos:
            self.agregar(h)

    def finalizar(self) -> None:
        """Marca el fin de la auditoria (para calcular la duracion)."""
        self.fin = datetime.now()

    def _resumen_por_severidad(self) -> dict:
        """
        Cuenta cuantos hallazgos hay de cada severidad.
        Devuelve algo como: {"critica": 1, "alta": 3, "media": 0, ...}
        """
        # Arrancamos el conteo en 0 para todas las severidades, para que
        # siempre aparezcan todas en el reporte aunque sean cero.
        conteo = {sev.value: 0 for sev in Severidad}
        for h in self.hallazgos:
            conteo[h.severidad.value] += 1
        return conteo

    def _hallazgos_ordenados(self) -> list[Hallazgo]:
        """Devuelve los hallazgos ordenados de mas grave a menos grave."""
        return sorted(
            self.hallazgos,
            key=lambda h: ORDEN_SEVERIDAD[h.severidad],
        )

    def construir(self) -> dict:
        """
        Arma el diccionario completo del reporte, listo para volcar a JSON.
        Esta es la estructura central que luego consumira el reporte HTML/PDF.
        """
        #Si no se llamo a finalizar(), lo hacemos ahora para tener una duracion
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

        # Añadir el analisis de riesgo si existe (Fase 5).
        if self.analisis_riesgo:
            datos["analisis_riesgo"] = self.analisis_riesgo

        return datos

    def guardar_json(self, carpeta: str = "resultados") -> str:
        """
        Guarda el reporte como archivo JSON dentro de la carpeta indicada.
        El nombre del archivo incluye la fecha y hora para no sobrescribir
        auditorias anteriores.

        Devuelve la ruta del archivo creado.
        """
        # Crea la carpeta si no existe (exist_ok evita error si ya existe).
        os.makedirs(carpeta, exist_ok=True)

        # Nombre unico basado en la fecha: reporte_2026-07-16_0130.json
        marca = self.inicio.strftime("%Y-%m-%d_%H%M%S")
        nombre_archivo = f"reporte_{marca}.json"
        ruta = os.path.join(carpeta, nombre_archivo)

        datos = self.construir()

        # ensure_ascii=False para que las tildes y ñ se guarden legibles.
        # indent=2 para que el JSON quede formateado y facil de leer.
        with open(ruta, "w", encoding="utf-8") as f:
            json.dump(datos, f, ensure_ascii=False, indent=2)

        return ruta

    def imprimir_resumen(self) -> None:
        """Muestra un resumen rapido por consola al terminar la auditoria."""
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


# Bloque de prueba: solo corre si ejecutas este archivo directamente.
# Crea unos hallazgos de ejemplo, arma el reporte y lo guarda.
if __name__ == "__main__":
    print("Probando el modulo de reporte...\n")

    rep = Reporte(
        objetivo="http://objetivo.local",
        nombre="Prueba de reporte",
    )

    # Creamos unos hallazgos de ejemplo (desordenados a proposito, para
    # comprobar que el reporte los ordena por severidad).
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