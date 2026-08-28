"""
modelo_hallazgo.py — Define la estructura de datos central del proyecto: la clase Hallazgo.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
import uuid


class Severidad(str, Enum):
    CRITICA = "critica"
    ALTA = "alta"
    MEDIA = "media"
    BAJA = "baja"
    INFORMATIVA = "informativa"


class CategoriaOWASP(str, Enum):
    """OWASP Top 10:2025."""
    A01 = "A01:2025 - Broken Access Control"
    A02 = "A02:2025 - Security Misconfiguration"
    A03 = "A03:2025 - Software Supply Chain Failures"
    A04 = "A04:2025 - Cryptographic Failures"
    A05 = "A05:2025 - Injection"
    A06 = "A06:2025 - Insecure Design"
    A07 = "A07:2025 - Authentication Failures"
    A08 = "A08:2025 - Software or Data Integrity Failures"
    A09 = "A09:2025 - Security Logging and Alerting Failures"
    A10 = "A10:2025 - Mishandling of Exceptional Conditions"


@dataclass
class Hallazgo:
    titulo: str
    categoria: CategoriaOWASP
    severidad: Severidad
    descripcion: str

    cvss: float | None = None
    evidencia: str = ""
    recomendacion: str = ""
    herramienta_origen: str = ""
    url_afectada: str = ""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def __post_init__(self):
        if isinstance(self.categoria, str):
            self.categoria = self._resolver_categoria(self.categoria)

        if isinstance(self.severidad, str):
            self.severidad = Severidad(self.severidad.lower())

        if self.cvss is not None:
            if not (0.0 <= self.cvss <= 10.0):
                raise ValueError(f"CVSS fuera de rango (0.0-10.0): {self.cvss}")

    @staticmethod
    def _resolver_categoria(valor: str) -> "CategoriaOWASP":
        clave = valor.strip().upper()
        if clave in CategoriaOWASP.__members__:
            return CategoriaOWASP[clave]
        for cat in CategoriaOWASP:
            if cat.value == valor:
                return cat
        raise ValueError(f"Categoria OWASP no reconocida: {valor}")

    def to_dict(self) -> dict:
        d = asdict(self)
        d["categoria"] = self.categoria.value
        d["severidad"] = self.severidad.value
        return d

    def __str__(self) -> str:
        cvss = f" | CVSS {self.cvss}" if self.cvss is not None else ""
        return (
            f"[{self.severidad.value.upper()}] {self.titulo}{cvss}\n"
            f"    Categoria: {self.categoria.value}\n"
            f"    {self.descripcion}"
        )


if __name__ == "__main__":
    h1 = Hallazgo(
        titulo="Falta la cabecera Content-Security-Policy",
        categoria="A02",
        severidad="media",
        descripcion="La respuesta HTTP no incluye CSP, facilita XSS.",
        cvss=5.3,
        evidencia="GET / -> respuesta sin cabecera 'Content-Security-Policy'",
        recomendacion="Anadir una cabecera CSP restrictiva en el servidor web.",
        herramienta_origen="modulo_cabeceras",
        url_afectada="http://objetivo.local/",
    )
    print(h1)
    print(h1.to_dict())

    try:
        Hallazgo(titulo="Prueba invalida", categoria="A01",
                 severidad="alta", descripcion="CVSS fuera de rango.", cvss=99.0)
    except ValueError as e:
        print(f"Error capturado correctamente: {e}")