"""Configuración base y constantes del motor SentinelSSH."""

from __future__ import annotations

from pathlib import Path
from typing import Any

BASE_DIR: Path = Path(__file__).resolve().parent.parent
DATA_DIR: Path = BASE_DIR / "data"

ARCHIVO_CONFIG: str = "config.json"
ARCHIVO_REPUTACION: str = "reputacion.json"
ARCHIVO_EVENTOS: str = "eventos.json"
ARCHIVO_MITIGACIONES: str = "mitigaciones.json"
ARCHIVO_ALERTAS: str = "alertas.json"
ARCHIVO_AUDITORIA: str = "auditoria.json"
ARCHIVO_ESTADO_AGENTE: str = "estado_agente.json"

MOTORES_FIREWALL_VALIDOS: tuple[str, ...] = ("iptables", "ufw", "nftables")
MAX_EVENTOS_ALMACENADOS: int = 500
MAX_ALERTAS_ALMACENADAS: int = 200
MAX_AUDITORIA_ALMACENADA: int = 1000


def obtener_configuracion_inicial() -> dict[str, Any]:
    """Devuelve la configuración predeterminada del detector SSH.

    Returns:
        dict[str, Any]: Diccionario con umbrales, ventana temporal,
            salvaguardas administrativas y opciones de notificación.
    """
    return {
        "umbral_alerta": 3,
        "umbral_limitacion": 5,
        "umbral_bloqueo": 10,
        "ventana_minutos": 10,
        "peso_usuario_invalido": 2,
        "horas_desbloqueo_auto": 24,
        "motor_firewall": "iptables",
        "ip_administrador": "203.0.113.10",
        "proteger_redes_privadas": True,
        "slack_webhook_url": "",
        "notificar_slack_en_etapa": "tasa_limitada",
        "rutas_log_monitoreadas": [
            "/var/log/auth.log",
            "/var/log/secure",
        ],
    }


def obtener_reputacion_inicial() -> list[dict[str, Any]]:
    """Genera las entradas iniciales de lista blanca y redes críticas.

    Returns:
        list[dict[str, Any]]: Lista de IPs y subredes CIDR protegidas
            para evitar falsos positivos y autobloqueos desde el inicio.
    """
    return [
        {
            "id": "rep-localhost",
            "objetivo": "127.0.0.1/32",
            "tipo": "lista_blanca",
            "etiqueta": "Loopback local del servidor",
            "protegida": True,
            "origen": "sistema",
            "creado_en": "2026-11-19T00:00:00Z",
            "incidentes": 0,
        },
        {
            "id": "rep-admin",
            "objetivo": "203.0.113.10/32",
            "tipo": "lista_blanca",
            "etiqueta": "IP del administrador principal",
            "protegida": True,
            "origen": "sistema",
            "creado_en": "2026-11-19T00:00:00Z",
            "incidentes": 0,
        },
        {
            "id": "rep-lan",
            "objetivo": "10.0.0.0/8",
            "tipo": "lista_blanca",
            "etiqueta": "Red interna corporativa",
            "protegida": True,
            "origen": "sistema",
            "creado_en": "2026-11-19T00:00:00Z",
            "incidentes": 0,
        },
        {
            "id": "rep-oficina",
            "objetivo": "192.168.10.0/24",
            "tipo": "lista_blanca",
            "etiqueta": "Oficina remota y VPN administrativa",
            "protegida": True,
            "origen": "manual",
            "creado_en": "2026-11-19T00:00:00Z",
            "incidentes": 0,
        },
        {
            "id": "rep-mal-1",
            "objetivo": "185.220.101.45/32",
            "tipo": "lista_negra",
            "etiqueta": "Nodo escáner SSH recurrente",
            "protegida": False,
            "origen": "deteccion",
            "creado_en": "2026-11-19T00:00:00Z",
            "incidentes": 14,
        },
    ]
