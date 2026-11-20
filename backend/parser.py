"""Analizador multiformato de registros de autenticación SSH en Linux."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import re
from typing import Any

# Expresiones regulares ancladas en los formatos reales de OpenSSH para
# /var/log/auth.log (Debian/Ubuntu) y /var/log/secure (RedHat/CentOS)
# evitando falsos emparejamientos ante payloads manipulados en el usuario.
PATRON_PREFIJO_SYSLOG: re.Pattern[str] = re.compile(
    r"^(?P<fecha>(?:\d{4}-\d{2}-\d{2}T\S+)|"
    r"(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}))\s+"
    r"(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s+(?P<mensaje>.+)$"
)

PATRON_FALLO_PASSWORD: re.Pattern[str] = re.compile(
    r"^Failed\s+(?P<metodo>password|publickey|keyboard-interactive/pam)\s+"
    r"for\s+(?:(?P<invalido>invalid user)\s+)?(?P<usuario>\S+)\s+"
    r"from\s+(?P<ip>[0-9a-fA-F:.]+)\s+port\s+(?P<puerto>\d+)"
)

PATRON_USUARIO_INVALIDO: re.Pattern[str] = re.compile(
    r"^Invalid\s+user\s+(?P<usuario>\S+)\s+"
    r"from\s+(?P<ip>[0-9a-fA-F:.]+)(?:\s+port\s+(?P<puerto>\d+))?"
)

PATRON_EXITO: re.Pattern[str] = re.compile(
    r"^Accepted\s+(?P<metodo>password|publickey|keyboard-interactive/pam)\s+"
    r"for\s+(?P<usuario>\S+)\s+from\s+(?P<ip>[0-9a-fA-F:.]+)\s+"
    r"port\s+(?P<puerto>\d+)"
)

PATRON_DEMASIADOS_FALLOS: re.Pattern[str] = re.compile(
    r"^Disconnecting\s+(?:authenticating|invalid)\s+user\s+"
    r"(?P<usuario>\S+)\s+(?P<ip>[0-9a-fA-F:.]+)\s+port\s+(?P<puerto>\d+):"
    r"\s+Too many authentication failures"
)

PATRON_CIERRE_SIN_AUTH: re.Pattern[str] = re.compile(
    r"^(?:Connection\s+(?:closed|reset)\s+by\s+(?:authenticating\s+user\s+"
    r"(?P<usuario>\S+)\s+)?|"
    r"Did\s+not\s+receive\s+identification\s+string\s+from\s+)"
    r"(?P<ip>[0-9a-fA-F:.]+)(?:\s+port\s+(?P<puerto>\d+))?"
)


def normalizar_fecha_syslog(fecha_texto: str) -> str:
    """Convierte marcas temporales syslog o ISO-8601 a formato UTC ISO-8601.

    Args:
        fecha_texto: Cadena de fecha extraída del inicio de la línea de log.

    Returns:
        str: Marca temporal normalizada en formato ISO-8601 UTC.
    """
    texto: str = fecha_texto.strip()
    if "T" in texto:
        try:
            dt_iso: datetime = datetime.fromisoformat(
                texto.replace("Z", "+00:00")
            )
            return dt_iso.astimezone(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
        except ValueError:
            pass

    anio_actual: int = datetime.now(timezone.utc).year
    try:
        # Los registros syslog clásicos omiten el año; se inyecta el año UTC
        # actual para mantener comparaciones cronológicas consistentes.
        dt_syslog: datetime = datetime.strptime(
            f"{anio_actual} {texto}", "%Y %b %d %H:%M:%S"
        )
        return dt_syslog.replace(tzinfo=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    except ValueError:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def inferir_sistema_origen(
    linea: str,
    sistema_sugerido: str = "auto",
) -> str:
    """Identifica si la línea corresponde a Debian/Ubuntu, RedHat o journald.

    Args:
        linea: Línea cruda del archivo de registro.
        sistema_sugerido: Sugerencia explícita del usuario o 'auto'.

    Returns:
        str: Identificador de origen ('debian_auth', 'redhat_secure' o
            'journald').
    """
    if sistema_sugerido in ("debian_auth", "redhat_secure", "journald"):
        return sistema_sugerido
    if re.match(r"^\d{4}-\d{2}-\d{2}T", linea):
        return "journald"
    if "rh-" in linea or "centos" in linea or "rhel" in linea:
        return "redhat_secure"
    return "debian_auth"


def calcular_hash_linea(linea: str) -> str:
    """Genera un identificador SHA-256 corto para deduplicación de eventos.

    Args:
        linea: Línea de log original sin espacios laterales.

    Returns:
        str: Hash hexadecimal de 16 caracteres.
    """
    resumen: str = hashlib.sha256(linea.strip().encode("utf-8")).hexdigest()
    return resumen[:16]


def analizar_linea(
    linea: str,
    sistema_sugerido: str = "auto",
) -> dict[str, Any] | None:
    """Extrae información estructurada de una línea de registro SSH.

    Args:
        linea: Línea cruda de /var/log/auth.log o /var/log/secure.
        sistema_sugerido: Origen esperado ('auto', 'debian_auth',
            'redhat_secure' o 'journald').

    Returns:
        dict[str, Any] | None: Evento normalizado con marca temporal, IP,
            usuario y resultado, o None si la línea no es un evento SSH útil.
    """
    linea_limpia: str = linea.strip()
    if not linea_limpia:
        return None

    coincidencia_base: re.Match[str] | None = PATRON_PREFIJO_SYSLOG.match(
        linea_limpia
    )
    if coincidencia_base is None:
        return None

    fecha_iso: str = normalizar_fecha_syslog(coincidencia_base.group("fecha"))
    mensaje: str = coincidencia_base.group("mensaje")
    sistema: str = inferir_sistema_origen(linea_limpia, sistema_sugerido)
    base_evento: dict[str, Any] = {
        "id": calcular_hash_linea(linea_limpia),
        "fecha": fecha_iso,
        "host": coincidencia_base.group("host"),
        "sistema": sistema,
        "linea_original": linea_limpia,
    }

    fallo: re.Match[str] | None = PATRON_FALLO_PASSWORD.match(mensaje)
    if fallo is not None:
        es_invalido: bool = fallo.group("invalido") is not None
        return {
            **base_evento,
            "ip": fallo.group("ip"),
            "puerto": int(fallo.group("puerto")),
            "usuario": fallo.group("usuario"),
            "metodo": fallo.group("metodo"),
            "estado": "usuario_invalido" if es_invalido else "fallo_auth",
            "es_fallo": True,
        }

    invalido: re.Match[str] | None = PATRON_USUARIO_INVALIDO.match(mensaje)
    if invalido is not None:
        puerto_raw: str | None = invalido.group("puerto")
        return {
            **base_evento,
            "ip": invalido.group("ip"),
            "puerto": int(puerto_raw) if puerto_raw else 22,
            "usuario": invalido.group("usuario"),
            "metodo": "desconocido",
            "estado": "usuario_invalido",
            "es_fallo": True,
        }

    exito: re.Match[str] | None = PATRON_EXITO.match(mensaje)
    if exito is not None:
        return {
            **base_evento,
            "ip": exito.group("ip"),
            "puerto": int(exito.group("puerto")),
            "usuario": exito.group("usuario"),
            "metodo": exito.group("metodo"),
            "estado": "exitoso",
            "es_fallo": False,
        }

    demasiados: re.Match[str] | None = PATRON_DEMASIADOS_FALLOS.match(mensaje)
    if demasiados is not None:
        return {
            **base_evento,
            "ip": demasiados.group("ip"),
            "puerto": int(demasiados.group("puerto")),
            "usuario": demasiados.group("usuario"),
            "metodo": "password",
            "estado": "exceso_intentos",
            "es_fallo": True,
        }

    cierre: re.Match[str] | None = PATRON_CIERRE_SIN_AUTH.match(mensaje)
    if cierre is not None:
        puerto_cierre: str | None = cierre.group("puerto")
        usuario_cierre: str | None = cierre.group("usuario")
        return {
            **base_evento,
            "ip": cierre.group("ip"),
            "puerto": int(puerto_cierre) if puerto_cierre else 22,
            "usuario": usuario_cierre or "desconocido",
            "metodo": "preauth",
            "estado": "desconexion_preauth",
            "es_fallo": True,
        }

    return None


def analizar_bloque_logs(
    texto_logs: str,
    sistema_sugerido: str = "auto",
) -> list[dict[str, Any]]:
    """Procesa múltiples líneas de registro y devuelve los eventos válidos.

    Args:
        texto_logs: Bloque de texto multilínea con registros SSH.
        sistema_sugerido: Tipo de registro sugerido o 'auto'.

    Returns:
        list[dict[str, Any]]: Eventos extraídos en orden de aparición.
    """
    eventos: list[dict[str, Any]] = []
    for linea in texto_logs.splitlines():
        evento: dict[str, Any] | None = analizar_linea(linea, sistema_sugerido)
        if evento is not None:
            eventos.append(evento)
    return eventos
