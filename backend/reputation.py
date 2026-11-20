"""Motor de reputación IP, listas blancas/negras y salvaguardas CIDR."""

from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
from typing import Any
import uuid


def validar_objetivo_ip_o_cidr(objetivo: str) -> str:
    """Valida y normaliza una dirección IP o subred CIDR IPv4/IPv6.

    Args:
        objetivo: Cadena con IP individual o rango CIDR (ej. '10.0.0.0/8').

    Returns:
        str: Representación CIDR normalizada en formato estricto.

    Raises:
        ValueError: Si la cadena no representa una IP o subred válida.
    """
    texto: str = objetivo.strip()
    red = ipaddress.ip_network(texto, strict=False)
    return str(red)


def ip_pertenece_a_red(ip_texto: str, objetivo_cidr: str) -> bool:
    """Comprueba si una dirección IP cae dentro de una IP o rango CIDR.

    Args:
        ip_texto: Dirección IP de origen a evaluar.
        objetivo_cidr: IP o subred CIDR almacenada en reputación.

    Returns:
        bool: True si la IP está contenida en el rango CIDR, False si no.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_texto.strip())
        red_obj = ipaddress.ip_network(objetivo_cidr.strip(), strict=False)
        return ip_obj in red_obj
    except ValueError:
        return False


def es_ip_protegida(
    ip_texto: str,
    configuracion: dict[str, Any],
    reputacion: list[dict[str, Any]],
) -> tuple[bool, str]:
    """Evalúa si una IP está excluida de bloqueo por salvaguardas críticas.

    Args:
        ip_texto: Dirección IP candidata a limitación o bloqueo.
        configuracion: Configuración activa del detector SSH.
        reputacion: Lista de entradas de reputación persistidas.

    Returns:
        tuple[bool, str]: Par (esta_protegida, motivo_proteccion).
    """
    try:
        ip_obj = ipaddress.ip_address(ip_texto.strip())
    except ValueError:
        return True, "Dirección IP con formato inválido"

    # Evitar autobloqueo de loopback y enlace local bajo cualquier escenario.
    if ip_obj.is_loopback or ip_obj.is_link_local:
        return True, "Dirección reservada de loopback o enlace local"

    ip_admin: str = str(configuracion.get("ip_administrador", "")).strip()
    if ip_admin and ip_pertenece_a_red(ip_texto, ip_admin):
        return True, f"IP protegida del administrador ({ip_admin})"

    if configuracion.get("proteger_redes_privadas", True) and ip_obj.is_private:
        return True, "Red privada RFC1918 protegida por política"

    for entrada in reputacion:
        if entrada.get("tipo") == "lista_blanca":
            objetivo: str = str(entrada.get("objetivo", ""))
            if ip_pertenece_a_red(ip_texto, objetivo):
                etiqueta: str = str(entrada.get("etiqueta", "Lista blanca"))
                return True, f"Incluida en lista blanca: {etiqueta}"

    return False, ""


def esta_en_lista_negra(
    ip_texto: str,
    reputacion: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Busca si una IP coincide con alguna entrada de lista negra conocida.

    Args:
        ip_texto: Dirección IP a consultar.
        reputacion: Lista de entradas de reputación almacenadas.

    Returns:
        dict[str, Any] | None: Entrada coincidente o None si no figura.
    """
    for entrada in reputacion:
        if entrada.get("tipo") == "lista_negra":
            if ip_pertenece_a_red(ip_texto, str(entrada.get("objetivo", ""))):
                return entrada
    return None


def crear_entrada_reputacion(
    objetivo: str,
    tipo: str,
    etiqueta: str,
    origen: str = "manual",
) -> dict[str, Any]:
    """Construye una nueva entrada validada para reputacion.json.

    Args:
        objetivo: IP o subred CIDR a registrar.
        tipo: Clasificación ('lista_blanca' o 'lista_negra').
        etiqueta: Descripción humana del propósito o motivo.
        origen: Fuente del registro ('manual', 'sistema', 'deteccion').

    Returns:
        dict[str, Any]: Registro listo para persistirse en JSON.

    Raises:
        ValueError: Si el tipo o el formato CIDR son inválidos.
    """
    if tipo not in ("lista_blanca", "lista_negra"):
        raise ValueError("El tipo debe ser 'lista_blanca' o 'lista_negra'.")

    cidr_normalizado: str = validar_objetivo_ip_o_cidr(objetivo)
    ahora: str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "id": f"rep-{uuid.uuid4().hex[:8]}",
        "objetivo": cidr_normalizado,
        "tipo": tipo,
        "etiqueta": etiqueta.strip() or "Sin descripción",
        "protegida": tipo == "lista_blanca",
        "origen": origen,
        "creado_en": ahora,
        "incidentes": 0,
    }
