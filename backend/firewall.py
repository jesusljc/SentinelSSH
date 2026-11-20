"""Generador de reglas de firewall y ciclo de vida de mitigaciones."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import ipaddress
from typing import Any


def generar_comando_firewall(
    ip_texto: str,
    etapa: str,
    motor: str,
) -> str:
    """Construye el comando de firewall exacto según el motor y la etapa.

    Args:
        ip_texto: Dirección IP atacante validada.
        etapa: Nivel de respuesta ('alerta', 'tasa_limitada' o 'bloqueado').
        motor: Herramienta Linux ('iptables', 'ufw' o 'nftables').

    Returns:
        str: Comando CLI listo para ejecutarse o auditarse en Linux.
    """
    ip_limpia: str = str(ipaddress.ip_address(ip_texto.strip()))
    if etapa == "alerta":
        return f"# Solo observación y alerta SOC para {ip_limpia}"

    if motor == "ufw":
        if etapa == "tasa_limitada":
            return f"ufw insert 1 limit from {ip_limpia} to any port 22 proto tcp"
        return f"ufw insert 1 deny from {ip_limpia} to any port 22 proto tcp"

    if motor == "nftables":
        if etapa == "tasa_limitada":
            return (
                f"nft add rule inet filter input ip saddr {ip_limpia} "
                "tcp dport 22 limit rate 3/minute accept"
            )
        return (
            f"nft insert rule inet filter input ip saddr {ip_limpia} "
            "tcp dport 22 drop"
        )

    # Motor por defecto: iptables clásico con hashlimit para etapa intermedia.
    if etapa == "tasa_limitada":
        return (
            f"iptables -I INPUT 1 -s {ip_limpia} -p tcp --dport 22 "
            "-m hashlimit --hashlimit-above 3/min --hashlimit-burst 3 "
            "--hashlimit-mode srcip --hashlimit-name ssh_limit -j DROP"
        )
    return f"iptables -I INPUT 1 -s {ip_limpia} -p tcp --dport 22 -j DROP"


def generar_comando_desbloqueo(ip_texto: str, etapa: str, motor: str) -> str:
    """Genera el comando para revertir una regla activa del firewall.

    Args:
        ip_texto: Dirección IP que se va a liberar.
        etapa: Etapa que estaba aplicada ('tasa_limitada' o 'bloqueado').
        motor: Motor de firewall ('iptables', 'ufw' o 'nftables').

    Returns:
        str: Comando CLI de eliminación de regla.
    """
    ip_limpia: str = str(ipaddress.ip_address(ip_texto.strip()))
    if motor == "ufw":
        accion: str = "limit" if etapa == "tasa_limitada" else "deny"
        return f"ufw delete {accion} from {ip_limpia} to any port 22 proto tcp"
    if motor == "nftables":
        return f"nft delete rule inet filter input # ip saddr {ip_limpia}"
    if etapa == "tasa_limitada":
        return (
            f"iptables -D INPUT -s {ip_limpia} -p tcp --dport 22 "
            "-m hashlimit --hashlimit-above 3/min --hashlimit-burst 3 "
            "--hashlimit-mode srcip --hashlimit-name ssh_limit -j DROP"
        )
    return f"iptables -D INPUT -s {ip_limpia} -p tcp --dport 22 -j DROP"


def calcular_expiracion_iso(horas: int) -> str:
    """Calcula la marca temporal ISO-8601 UTC de desbloqueo automático.

    Args:
        horas: Cantidad de horas antes de liberar la IP (ej. 24 o 48).

    Returns:
        str: Fecha y hora UTC futura en formato ISO-8601.
    """
    horas_seguras: int = max(1, min(int(horas), 168))
    objetivo: datetime = datetime.now(timezone.utc) + timedelta(
        hours=horas_seguras
    )
    return objetivo.strftime("%Y-%m-%dT%H:%M:%SZ")


def purgar_mitigaciones_expiradas(
    mitigaciones: list[dict[str, Any]],
    ahora_utc: datetime | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Separa mitigaciones aún vigentes de aquellas cuyo plazo ya expiró.

    Args:
        mitigaciones: Lista actual de mitigaciones registradas.
        ahora_utc: Instante de referencia UTC opcional para pruebas.

    Returns:
        tuple[list[dict[str, Any]], list[dict[str, Any]]]: Tupla con
            (mitigaciones_activas, mitigaciones_expiradas).
    """
    referencia: datetime = ahora_utc or datetime.now(timezone.utc)
    activas: list[dict[str, Any]] = []
    expiradas: list[dict[str, Any]] = []

    for item in mitigaciones:
        if item.get("estado") != "activa":
            continue
        expira_str: str | None = item.get("expira_en")
        if not expira_str:
            activas.append(item)
            continue
        try:
            expira_dt: datetime = datetime.fromisoformat(
                expira_str.replace("Z", "+00:00")
            )
            if expira_dt <= referencia:
                expiradas.append(item)
            else:
                activas.append(item)
        except ValueError:
            activas.append(item)

    return activas, expiradas
