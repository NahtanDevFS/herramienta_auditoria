"""
tls_ssl.py  (modulo de deteccion - A04: Cryptographic Failures)
Analiza la configuracion TLS/SSL del objetivo usando la libreria sslyze.
Detecta los problemas criptograficos mas comunes:

  - Protocolos obsoletos habilitados (SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1).
  - Certificado no confiable (cadena invalida o no reconocida).
  - Certificado que no coincide con el hostname.
  - Certificado caducado o proximo a caducar.
  - Firma debil (SHA-1) en la cadena de confianza.

Este modulo es distinto a los anteriores: no usa 'requests', sino sslyze,
que abre conexiones TLS reales al puerto 443 y examina la negociacion a
fondo. Solo tiene sentido para objetivos HTTPS.

Mantiene el mismo patron de siempre:
    def ejecutar(config, logger) -> list[Hallazgo]
"""

import logging
from datetime import datetime, timezone
from urllib.parse import urlparse

from core.modelo_hallazgo import Hallazgo

# sslyze se importa dentro de las funciones para que, si no esta instalado,
# el error se maneje con un mensaje claro en vez de romper todo el programa
# al arrancar.

ORIGEN = "modulo_tls_ssl"

# Dias antes de la caducidad a partir de los cuales avisamos.
DIAS_AVISO_CADUCIDAD = 30

# Protocolos considerados obsoletos/inseguros y la severidad de tenerlos.
PROTOCOLOS_OBSOLETOS = {
    "ssl_2_0_cipher_suites": ("SSL 2.0", "critica", 9.1),
    "ssl_3_0_cipher_suites": ("SSL 3.0", "alta", 7.5),
    "tls_1_0_cipher_suites": ("TLS 1.0", "media", 5.3),
    "tls_1_1_cipher_suites": ("TLS 1.1", "media", 5.3),
}


def ejecutar(config: dict, logger: logging.Logger) -> list[Hallazgo]:
    """
    Punto de entrada del modulo (lo llama main.py).

    Solo actua sobre objetivos HTTPS. Si el objetivo es HTTP, lo indica y
    devuelve lista vacia (el analisis TLS no aplica).
    """
    objetivo = config["objetivo"]["url"].strip()
    parsed = urlparse(objetivo)

    hallazgos: list[Hallazgo] = []

    # El analisis TLS solo aplica a HTTPS.
    if parsed.scheme != "https":
        logger.info(
            "[tls_ssl] El objetivo no usa HTTPS; el analisis TLS/SSL no aplica. "
            "Se omite este modulo."
        )
        return hallazgos

    hostname = parsed.hostname
    puerto = parsed.port or 443

    logger.info(f"[tls_ssl] Analizando TLS/SSL de {hostname}:{puerto}")

    # --- Importar sslyze de forma segura ---
    try:
        from sslyze import (
            Scanner, ServerScanRequest, ServerNetworkLocation, ScanCommand,
        )
        from sslyze.errors import ServerHostnameCouldNotBeResolved
    except ImportError:
        logger.error(
            "[tls_ssl] La libreria 'sslyze' no esta instalada. "
            "Instalala con: pip install sslyze"
        )
        return hallazgos

    # --- Preparar el escaneo ---
    try:
        request = ServerScanRequest(
            server_location=ServerNetworkLocation(hostname=hostname, port=puerto),
            scan_commands={
                ScanCommand.CERTIFICATE_INFO,
                ScanCommand.SSL_2_0_CIPHER_SUITES,
                ScanCommand.SSL_3_0_CIPHER_SUITES,
                ScanCommand.TLS_1_0_CIPHER_SUITES,
                ScanCommand.TLS_1_1_CIPHER_SUITES,
                ScanCommand.TLS_1_2_CIPHER_SUITES,
                ScanCommand.TLS_1_3_CIPHER_SUITES,
            },
        )
    except ServerHostnameCouldNotBeResolved:
        logger.error(f"[tls_ssl] No se pudo resolver el hostname: {hostname}")
        return hallazgos

    scanner = Scanner()
    scanner.queue_scans([request])

    # --- Procesar resultados ---
    for result in scanner.get_results():
        if result.scan_status.name != "COMPLETED":
            logger.error(
                f"[tls_ssl] El escaneo no se completo (estado: "
                f"{result.scan_status.name}). Puede que el servidor no responda "
                f"en el puerto {puerto}."
            )
            continue

        attempts = result.scan_result

        # 1) Protocolos obsoletos habilitados.
        hallazgos.extend(
            _revisar_protocolos(attempts, objetivo, logger)
        )

        # 2) Analisis del certificado.
        hallazgos.extend(
            _revisar_certificado(attempts, hostname, objetivo, logger)
        )

    logger.info(
        f"[tls_ssl] Analisis terminado. {len(hallazgos)} hallazgo(s)."
    )
    return hallazgos


def _revisar_protocolos(attempts, objetivo: str, logger) -> list[Hallazgo]:
    """Genera un hallazgo por cada protocolo obsoleto que este habilitado."""
    hallazgos: list[Hallazgo] = []

    for atributo, (nombre, severidad, cvss) in PROTOCOLOS_OBSOLETOS.items():
        intento = getattr(attempts, atributo, None)
        if intento is None or intento.status.name != "COMPLETED":
            continue

        # Si hay cipher suites aceptadas, el protocolo esta habilitado.
        aceptadas = intento.result.accepted_cipher_suites
        if aceptadas:
            hallazgos.append(Hallazgo(
                titulo=f"Protocolo obsoleto habilitado: {nombre}",
                categoria="A04",
                severidad=severidad,
                descripcion=(
                    f"El servidor acepta conexiones mediante {nombre}, un "
                    f"protocolo obsoleto con debilidades criptograficas "
                    f"conocidas. Debe deshabilitarse."
                ),
                cvss=cvss,
                evidencia=(
                    f"{nombre}: {len(aceptadas)} cipher suite(s) aceptada(s) "
                    f"por el servidor."
                ),
                recomendacion=(
                    f"Deshabilitar {nombre} en la configuracion del servidor y "
                    f"permitir unicamente TLS 1.2 y TLS 1.3."
                ),
                herramienta_origen=ORIGEN,
                url_afectada=objetivo,
            ))
            logger.info(f"[tls_ssl] Protocolo obsoleto habilitado: {nombre}")

    return hallazgos


def _revisar_certificado(attempts, hostname, objetivo, logger) -> list[Hallazgo]:
    """Analiza el certificado: confianza, hostname, caducidad y firma."""
    hallazgos: list[Hallazgo] = []

    cert_intento = attempts.certificate_info
    if cert_intento.status.name != "COMPLETED":
        logger.warning("[tls_ssl] No se pudo obtener informacion del certificado.")
        return hallazgos

    deployments = cert_intento.result.certificate_deployments
    if not deployments:
        return hallazgos

    dep = deployments[0]
    leaf = dep.received_certificate_chain[0]

    # --- Confianza de la cadena ---
    # path_validation_results valida el certificado frente a varios almacenes
    # de confianza (Mozilla, Apple, Windows...). Consideramos el certificado
    # NO confiable solo si falla en TODOS y ademas los errores indican un
    # problema real del certificado (no un trust store desactualizado en la
    # maquina que ejecuta la auditoria).
    validaciones = dep.path_validation_results
    confiable = any(v.was_validation_successful for v in validaciones)

    if not confiable:
        # Recoger los mensajes de error de validacion para dar evidencia y
        # para distinguir un problema real del certificado.
        errores = [
            str(v.validation_error)
            for v in validaciones
            if v.validation_error is not None
        ]
        # Errores que apuntan a un problema REAL del certificado (no del store).
        indicios_reales = (
            "self signed", "self-signed", "expired", "hostname",
            "unable to get local issuer", "certificate has expired",
            "unable to get issuer", "invalid",
            "not valid at validation time",  # certificado caducado o aun no valido
            "no candidates", "cannot find matching",  # cadena/CA no reconocida
        )
        texto_errores = " ".join(errores).lower()
        es_problema_real = any(ind in texto_errores for ind in indicios_reales)

        if es_problema_real:
            evidencia = "; ".join(errores[:3]) if errores else \
                "Validacion fallida en todos los trust stores."
            hallazgos.append(Hallazgo(
                titulo="Certificado TLS no confiable",
                categoria="A04",
                severidad="alta",
                descripcion=(
                    "El certificado del servidor no pudo validarse contra los "
                    "almacenes de confianza reconocidos. Puede ser autofirmado, "
                    "estar caducado, tener una cadena incompleta o estar emitido "
                    "por una CA no reconocida."
                ),
                cvss=7.4,
                evidencia=evidencia,
                recomendacion=(
                    "Instalar un certificado emitido por una CA reconocida e "
                    "incluir la cadena intermedia completa."
                ),
                herramienta_origen=ORIGEN,
                url_afectada=objetivo,
            ))
            logger.info("[tls_ssl] Certificado no confiable (problema real).")
        else:
            # La validacion fallo pero sin indicios de problema real: es muy
            # probable que el trust store de la maquina este desactualizado.
            logger.warning(
                "[tls_ssl] La validacion de la cadena fallo en todos los trust "
                "stores, pero sin indicios de un problema real del certificado. "
                "Esto suele deberse a trust stores desactualizados en el equipo "
                "que ejecuta la auditoria. No se reporta como hallazgo. "
                f"Errores: {errores[:2]}"
            )

    # --- Coincidencia con el hostname ---
    # Usamos la libreria cryptography para comprobar si el hostname esta en
    # el certificado (CN o SAN).
    if not _hostname_coincide(leaf, hostname):
        hallazgos.append(Hallazgo(
            titulo="El certificado no coincide con el hostname",
            categoria="A04",
            severidad="alta",
            descripcion=(
                f"El certificado presentado no incluye el hostname '{hostname}' "
                f"en su Common Name ni en los Subject Alternative Names. Los "
                f"navegadores rechazaran la conexion o mostraran advertencias."
            ),
            cvss=7.4,
            evidencia=f"Hostname solicitado: {hostname}",
            recomendacion=(
                "Emitir un certificado que incluya el hostname correcto en los "
                "Subject Alternative Names (SAN)."
            ),
            herramienta_origen=ORIGEN,
            url_afectada=objetivo,
        ))
        logger.info("[tls_ssl] Certificado no coincide con hostname.")

    # --- Caducidad ---
    ahora = datetime.now(timezone.utc)
    not_after = leaf.not_valid_after_utc
    dias_restantes = (not_after - ahora).days

    if dias_restantes < 0:
        hallazgos.append(Hallazgo(
            titulo="Certificado TLS caducado",
            categoria="A04",
            severidad="alta",
            descripcion=(
                f"El certificado caduco hace {abs(dias_restantes)} dia(s). "
                f"Los navegadores bloquearan el acceso al sitio."
            ),
            cvss=7.4,
            evidencia=f"Fecha de expiracion: {not_after.isoformat()}",
            recomendacion="Renovar el certificado de inmediato.",
            herramienta_origen=ORIGEN,
            url_afectada=objetivo,
        ))
        logger.info("[tls_ssl] Certificado caducado.")
    elif dias_restantes < DIAS_AVISO_CADUCIDAD:
        hallazgos.append(Hallazgo(
            titulo="Certificado TLS proximo a caducar",
            categoria="A04",
            severidad="baja",
            descripcion=(
                f"El certificado caduca en {dias_restantes} dia(s). Conviene "
                f"renovarlo antes de que expire para evitar interrupciones."
            ),
            cvss=2.6,
            evidencia=f"Fecha de expiracion: {not_after.isoformat()}",
            recomendacion="Programar la renovacion del certificado.",
            herramienta_origen=ORIGEN,
            url_afectada=objetivo,
        ))
        logger.info(f"[tls_ssl] Certificado caduca en {dias_restantes} dias.")

    # --- Firma SHA-1 (debil) en la cadena ---
    if dep.verified_chain_has_sha1_signature:
        hallazgos.append(Hallazgo(
            titulo="Cadena de certificados con firma SHA-1",
            categoria="A04",
            severidad="media",
            descripcion=(
                "La cadena de certificados usa el algoritmo de firma SHA-1, "
                "considerado inseguro por su vulnerabilidad a colisiones."
            ),
            cvss=5.3,
            evidencia="verified_chain_has_sha1_signature = True",
            recomendacion="Reemitir los certificados usando SHA-256 o superior.",
            herramienta_origen=ORIGEN,
            url_afectada=objetivo,
        ))
        logger.info("[tls_ssl] Cadena con firma SHA-1.")

    return hallazgos


def _hostname_coincide(certificado, hostname: str) -> bool:
    """
    Comprueba si el hostname aparece en el certificado (CN o SAN).
    Devuelve True si coincide. Ante cualquier duda o error, devuelve True
    para NO generar un falso positivo (preferimos no alarmar sin certeza).
    """
    try:
        from cryptography.x509.oid import ExtensionOID
        # Buscar en los Subject Alternative Names (lo correcto hoy en dia).
        try:
            ext = certificado.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            from cryptography.x509 import DNSName
            nombres = ext.value.get_values_for_type(DNSName)
            for nombre in nombres:
                if _coincide_con_comodin(nombre, hostname):
                    return True
        except Exception:
            pass

        # Respaldo: revisar el Common Name.
        from cryptography.x509.oid import NameOID
        cn_attrs = certificado.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        for attr in cn_attrs:
            if _coincide_con_comodin(attr.value, hostname):
                return True

        return False
    except Exception:
        # Ante error inesperado, no marcamos falso positivo.
        return True


def _coincide_con_comodin(patron: str, hostname: str) -> bool:
    """Compara un nombre del certificado (que puede ser *.dominio) con el host."""
    patron = patron.lower().strip()
    hostname = hostname.lower().strip()
    if patron == hostname:
        return True
    # Comodin tipo *.ejemplo.com : cubre un solo nivel de subdominio.
    if patron.startswith("*."):
        base = patron[2:]
        partes = hostname.split(".", 1)
        if len(partes) == 2 and partes[1] == base:
            return True
    return False


# Prueba independiente:
#     python3 -m modulos.tls_ssl
# Escanea un sitio HTTPS real.
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    log = logging.getLogger("prueba")

    config_prueba = {
        "objetivo": {"url": "https://example.com"},
        "opciones": {},
    }

    print("Probando el modulo tls_ssl contra https://example.com ...\n")
    resultados = ejecutar(config_prueba, log)

    print(f"\nSe generaron {len(resultados)} hallazgos:\n")
    for h in resultados:
        print(h)
        print()
    if not resultados:
        print("(Sin hallazgos: la configuracion TLS del objetivo es correcta.)")