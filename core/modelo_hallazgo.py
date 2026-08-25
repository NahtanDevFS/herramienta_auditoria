"""
modelo_hallazgo.py Define la estructura de datos central del proyecto: la clase Hallazgo.

Cada vulnerabilidad, mala configuración o problema detectado por cualquier
modulo de la herramienta se representa como un objeto Hallazgo. Esto garantiza
que, sin importar de que modulo o herramienta externa provenga (nmap, nuclei,
un chequeo propio de cabeceras, etc.), todo se guarde con el MISMO formato.
Ese formato unico es lo que luego permite:
  - Consolidar todos los resultados en un solo JSON.
  - Calcular el riesgo de forma homogenea.
  - Generar el reporte final agrupado por categoria OWASP.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
import uuid


class Severidad(str, Enum):
    """
    Niveles de severidad posibles para un hallazgo.
    Hereda de str ademas de Enum para que el valor se serialice como texto
    plano ("alta", "media"...) al exportar a JSON, sin pasos extra.
    """
    CRITICA = "critica"
    ALTA = "alta"
    MEDIA = "media"
    BAJA = "baja"
    INFORMATIVA = "informativa"


class CategoriaOWASP(str, Enum):
    """
    Las 10 categorias del OWASP Top 10.
    Cada hallazgo se etiqueta con una de estas para poder agrupar el
    reporte final por categoria, que es como se estructura una auditoria
    profesional.
    """
    A01 = "A01:2021 - Broken Access Control"
    A02 = "A02:2021 - Cryptographic Failures"
    A03 = "A03:2021 - Injection"
    A04 = "A04:2021 - Insecure Design"
    A05 = "A05:2021 - Security Misconfiguration"
    A06 = "A06:2021 - Vulnerable and Outdated Components"
    A07 = "A07:2021 - Identification and Authentication Failures"
    A08 = "A08:2021 - Software and Data Integrity Failures"
    A09 = "A09:2021 - Security Logging and Monitoring Failures"
    A10 = "A10:2021 - Server-Side Request Forgery (SSRF)"


@dataclass
class Hallazgo:
    """
    Representa un unico hallazgo de la auditoria.

    Campos obligatorios (deben darse al crear el hallazgo):
        titulo         : Nombre corto y claro del problema.
        categoria      : Categoria OWASP a la que pertenece.
        severidad      : Gravedad del hallazgo.
        descripcion    : Explicacion de que es y por que es un problema.

    Campos opcionales (tienen valor por defecto):
        cvss               : Puntuacion CVSS 0.0-10.0. None si no aplica.
        evidencia          : Prueba concreta (cabecera, respuesta, payload...).
        recomendacion      : Como corregirlo.
        herramienta_origen : Que modulo o herramienta lo detecto.
        url_afectada       : URL o endpoint especifico donde se encontro.

    Campos automaticos (se generan solos, no se pasan al crear):
        id        : Identificador unico del hallazgo.
        timestamp : Momento exacto de deteccion (formato ISO 8601).
    """

    #Obligatorios 
    titulo: str
    categoria: CategoriaOWASP
    severidad: Severidad
    descripcion: str

    #Opcionales
    cvss: float | None = None
    evidencia: str = ""
    recomendacion: str = ""
    herramienta_origen: str = ""
    url_afectada: str = ""

    #Automaticos
    #default_factory se usa cuando el valor por defecto debe CALCULARSE
    #en el momento de crear cada objeto (no compartirse entre todos)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def __post_init__(self):
        """
        Se ejecuta automaticamente justo despues de crear el objeto.
        Lo usamos para validar que los datos tengan sentido y para
        aceptar valores en texto (comodo cuando el dato viene de un
        parser de una herramienta externa).
        """
        # Permitir pasar la categoria como texto ("A05") y convertirla
        if isinstance(self.categoria, str):
            self.categoria = self._resolver_categoria(self.categoria)

        # Permitir pasar la severidad como texto ("alta") y convertirla
        if isinstance(self.severidad, str):
            self.severidad = Severidad(self.severidad.lower())

        # Validar el rango del CVSS si se proporciono
        if self.cvss is not None:
            if not (0.0 <= self.cvss <= 10.0):
                raise ValueError(
                    f"CVSS fuera de rango (0.0-10.0): {self.cvss}"
                )

    @staticmethod
    def _resolver_categoria(valor: str) -> "CategoriaOWASP":
        """
        Acepta tanto la clave corta ('A05') como el valor completo
        ('A05:2021 - Security Misconfiguration') y devuelve el Enum.
        """
        clave = valor.strip().upper()
        # Caso 1: se paso la clave corta tipo "A05"
        if clave in CategoriaOWASP.__members__:
            return CategoriaOWASP[clave]
        # Caso 2: se paso el valor completo
        for cat in CategoriaOWASP:
            if cat.value == valor:
                return cat
        raise ValueError(f"Categoria OWASP no reconocida: {valor}")

    def to_dict(self) -> dict:
        """
        Convierte el hallazgo a un diccionario listo para volcar a JSON.
        Los Enum se guardan por su .value (texto legible).
        """
        d = asdict(self)
        d["categoria"] = self.categoria.value
        d["severidad"] = self.severidad.value
        return d

    def __str__(self) -> str:
        """Representacion compacta y legible para logs o consola."""
        cvss = f" | CVSS {self.cvss}" if self.cvss is not None else ""
        return (
            f"[{self.severidad.value.upper()}] {self.titulo}{cvss}\n"
            f"    Categoria: {self.categoria.value}\n"
            f"    {self.descripcion}"
        )


#Bloque de prueba: solo se ejecuta si corro este archivo directamente (python modelo_hallazgo.py). No se ejecuta al importarlo desde otro modulo.
# Sirve para comprobar que la clase funciona antes de seguir.
if __name__ == "__main__":
    print("Probando la clase Hallazgo...\n")

    # Ejemplo 1 creacion normal, pasando los Enum como texto
    h1 = Hallazgo(
        titulo="Falta la cabecera Content-Security-Policy",
        categoria="A05",               # se acepta texto corto
        severidad="media",             # se acepta texto
        descripcion=(
            "La respuesta HTTP no incluye la cabecera CSP, lo que facilita "
            "ataques de tipo XSS e inyeccion de contenido."
        ),
        cvss=5.3,
        evidencia="GET / -> respuesta sin cabecera 'Content-Security-Policy'",
        recomendacion="Anadir una cabecera CSP restrictiva en el servidor web.",
        herramienta_origen="modulo_cabeceras",
        url_afectada="http://objetivo.local/",
    )

    print(h1)                          # usa __str__
    print("\nComo diccionario / JSON:")
    print(h1.to_dict())
    print(f"\nID generado automaticamente: {h1.id}")
    print(f"Timestamp: {h1.timestamp}")

    # Ejemplo 2 comprobar que la validacion del CVSS funciona
    print("\nProbando validacion de CVSS invalido (deberia fallar)...")
    try:
        Hallazgo(
            titulo="Prueba invalida",
            categoria="A01",
            severidad="alta",
            descripcion="Esto deberia lanzar un error por CVSS fuera de rango.",
            cvss=99.0,
        )
    except ValueError as e:
        print(f"    Error capturado correctamente: {e}")

    print("\nTodo funciona.")