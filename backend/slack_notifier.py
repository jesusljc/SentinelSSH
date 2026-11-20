"""Cliente de notificaciones en tiempo real mediante Webhook de Slack."""

from __future__ import annotations

import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def validar_url_webhook_slack(url: str) -> bool:
    """Verifica que la URL tenga un esquema HTTPS válido para webhooks.

    Args:
        url: URL del Incoming Webhook configurada por el administrador.

    Returns:
        bool: True si es una URL HTTPS bien formada, False en caso contrario.
    """
    limpia: str = url.strip()
    return limpia.startswith("https://hooks.slack.com/") or limpia.startswith(
        "https://"
    )


def construir_payload_slack(
    titulo: str,
    ip_origen: str,
    etapa: str,
    intentos: int,
    usuarios: list[str],
    comando_firewall: str,
    detalle: str,
) -> dict[str, Any]:
    """Arma un mensaje enriquecido compatible con Slack Incoming Webhooks.

    Args:
        titulo: Encabezado breve de la alerta.
        ip_origen: Dirección IP origen del incidente.
        etapa: Etapa de escalamiento ('alerta', 'tasa_limitada' o 'bloqueado').
        intentos: Número de intentos fallidos acumulados en la ventana.
        usuarios: Lista de usuarios objetivo observados.
        comando_firewall: Regla generada o aplicada.
        detalle: Descripción adicional del contexto.

    Returns:
        dict[str, Any]: Carga JSON lista para enviar a Slack.
    """
    usuarios_texto: str = ", ".join(
        usuarios[:6]) if usuarios else "desconocido"
    texto_resumen: str = (
        f"[SentinelSSH] {titulo} | IP: {ip_origen} | Etapa: {etapa} | "
        f"Intentos: {intentos}"
    )
    return {
        "text": texto_resumen,
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"SentinelSSH · {titulo}"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*IP Origen:*\n`{ip_origen}`"},
                    {"type": "mrkdwn", "text": f"*Etapa:*\n{etapa}"},
                    {"type": "mrkdwn", "text": f"*Intentos:*\n{intentos}"},
                    {"type": "mrkdwn", "text": f"*Usuarios:*\n`{usuarios_texto}`"},
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Detalle:* {detalle}\n```{comando_firewall}```",
                },
            },
        ],
    }


def enviar_alerta_slack(
    webhook_url: str,
    payload: dict[str, Any],
    timeout_segundos: int = 6,
) -> tuple[bool, str]:
    """Envía una petición HTTP POST al webhook de Slack desde el servidor.

    Args:
        webhook_url: URL HTTPS del webhook destino.
        payload: Diccionario JSON formateado para Slack.
        timeout_segundos: Tiempo máximo de espera de red.

    Returns:
        tuple[bool, str]: Par (enviado_con_exito, mensaje_estado).
    """
    url_limpia: str = webhook_url.strip()
    if not url_limpia:
        return False, "No hay Webhook de Slack configurado."
    if not validar_url_webhook_slack(url_limpia):
        return False, "La URL del webhook debe comenzar con https://."

    cuerpo: bytes = json.dumps(payload).encode("utf-8")
    peticion: Request = Request(
        url_limpia,
        data=cuerpo,
        headers={"Content-Type": "application/json; charset=utf-8"},
        method="POST",
    )
    try:
        # Se ejecuta desde el backend para evitar bloqueos CORS del navegador
        # y mantener el secreto del webhook fuera del cliente web.
        with urlopen(peticion, timeout=timeout_segundos) as respuesta:
            codigo: int = getattr(respuesta, "status", 200)
            if 200 <= codigo < 300:
                return True, f"Alerta entregada a Slack (HTTP {codigo})."
            return False, f"Slack respondió con código HTTP {codigo}."
    except HTTPError as err:
        return False, f"Error HTTP de Slack ({err.code}): {err.reason}"
    except URLError as err:
        return False, f"No se pudo conectar con Slack: {err.reason}"
    except OSError as err:
        return False, f"Error de red enviando a Slack: {err}"
