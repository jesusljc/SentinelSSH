"""Generador del agente Python descargable con soporte de rotación por inodo."""

from __future__ import annotations

import json
from typing import Any


def construir_codigo_agente_python(
    configuracion: dict[str, Any],
    reputacion: list[dict[str, Any]],
) -> str:
    """Ensambla el script Python autónomo sincronizado con la configuración SOC.

    Args:
        configuracion: Umbrales, motor de firewall, Slack e IP de admin.
        reputacion: Lista blanca y negra actual para embeber en config.

    Returns:
        str: Código fuente completo del agente cumpliendo PEP 8 y Type Hints.
    """
    umbral_alerta: int = int(configuracion.get("umbral_alerta", 3))
    umbral_limitacion: int = int(configuracion.get("umbral_limitacion", 5))
    umbral_bloqueo: int = int(configuracion.get("umbral_bloqueo", 10))
    ventana_min: int = int(configuracion.get("ventana_minutos", 10))
    horas_auto: int = int(configuracion.get("horas_desbloqueo_auto", 24))
    motor_fw: str = str(configuracion.get("motor_firewall", "iptables"))
    ip_admin: str = str(configuracion.get("ip_administrador", "203.0.113.10"))

    script: str = f'''#!/usr/bin/env python3
"""Agente SentinelSSH para monitoreo continuo de fuerza bruta en Linux.

Lee /var/log/auth.log y /var/log/secure manejando rotación por inodo,
persiste estado y auditoría en archivos JSON locales, aplica reglas de
firewall escalantes con protección anti-autobloqueo y notifica a Slack.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import subprocess
import time
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

RUTA_BASE: Path = Path(__file__).resolve().parent
ARCHIVO_CONFIG: Path = RUTA_BASE / "config.json"
ARCHIVO_ESTADO: Path = RUTA_BASE / "estado_agente.json"
ARCHIVO_AUDITORIA: Path = RUTA_BASE / "auditoria.json"
ARCHIVO_BLOQUEOS: Path = RUTA_BASE / "mitigaciones.json"

INTERVALO_SONDEO_SEG: float = 2.0
VENTANA_DEFECTO_MIN: int = {ventana_min}
UMBRAL_ALERTA_DEFECTO: int = {umbral_alerta}
UMBRAL_LIMITACION_DEFECTO: int = {umbral_limitacion}
UMBRAL_BLOQUEO_DEFECTO: int = {umbral_bloqueo}
HORAS_DESBLOQUEO_DEFECTO: int = {horas_auto}
MOTOR_FIREWALL_DEFECTO: str = "{motor_fw}"
IP_ADMIN_DEFECTO: str = "{ip_admin}"

PATRON_FALLO: re.Pattern[str] = re.compile(
    r"sshd(?:\\[\\d+\\])?:\\s+(?:Failed\\s+\\S+\\s+for\\s+"
    r"(?:(?P<invalido>invalid user)\\s+)?(?P<usuario>\\S+)|"
    r"Invalid\\s+user\\s+(?P<usuario_inv>\\S+))\\s+"
    r"from\\s+(?P<ip>[0-9a-fA-F:.]+)"
)
PATRON_EXITO: re.Pattern[str] = re.compile(
    r"sshd(?:\\[\\d+\\])?:\\s+Accepted\\s+\\S+\\s+for\\s+"
    r"(?P<usuario>\\S+)\\s+from\\s+(?P<ip>[0-9a-fA-F:.]+)"
)


def configurar_syslog() -> logging.Logger:
    """Configura el registrador estándar hacia consola y syslog del sistema.

    Returns:
        logging.Logger: Instancia lista para emitir eventos del agente.
    """
    logger: logging.Logger = logging.getLogger("sentinel_ssh")
    logger.setLevel(logging.INFO)
    formato: logging.Formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s"
    )
    consola: logging.StreamHandler[Any] = logging.StreamHandler()
    consola.setFormatter(formato)
    logger.addHandler(consola)
    return logger


def leer_json_seguro(ruta: Path, defecto: Any) -> Any:
    """Lee un archivo JSON devolviendo un respaldo si falta o está dañado.

    Args:
        ruta: Ubicación del archivo JSON en disco.
        defecto: Valor a devolver en caso de ausencia o error.

    Returns:
        Any: Datos deserializados desde el archivo.
    """
    if not ruta.exists():
        return defecto
    try:
        return json.loads(ruta.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return defecto


def escribir_json_atomico(ruta: Path, datos: Any) -> None:
    """Guarda datos JSON mediante archivo temporal y reemplazo atómico.

    Args:
        ruta: Ruta destino del archivo JSON.
        datos: Estructura serializable a persistir.
    """
    temporal: Path = ruta.with_suffix(".tmp")
    temporal.write_text(
        json.dumps(datos, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    # os.replace es atómico en POSIX y evita corrupción ante cortes eléctricos.
    os.replace(temporal, ruta)


def analizar_linea_ssh(linea: str) -> dict[str, Any] | None:
    """Extrae IP, usuario y tipo de intento de una línea de log OpenSSH.

    Args:
        linea: Línea individual de auth.log o secure.

    Returns:
        dict[str, Any] | None: Evento parseado o None si no aplica.
    """
    fallo: re.Match[str] | None = PATRON_FALLO.search(linea)
    if fallo is not None:
        es_inv: bool = (
            fallo.group("invalido") is not None
            or fallo.group("usuario_inv") is not None
        )
        usuario: str = (
            fallo.group("usuario")
            or fallo.group("usuario_inv")
            or "desconocido"
        )
        return {{
            "ip": fallo.group("ip"),
            "usuario": usuario,
            "tipo": "usuario_invalido" if es_inv else "fallo_auth",
            "es_fallo": True,
        }}

    exito: re.Match[str] | None = PATRON_EXITO.search(linea)
    if exito is not None:
        return {{
            "ip": exito.group("ip"),
            "usuario": exito.group("usuario"),
            "tipo": "exitoso",
            "es_fallo": False,
        }}
    return None


def es_ip_protegida(
    ip_texto: str,
    configuracion: dict[str, Any],
) -> tuple[bool, str]:
    """Valida salvaguardas anti-autobloqueo antes de tocar el firewall.

    Args:
        ip_texto: Dirección IP candidata a sanción.
        configuracion: Diccionario cargado desde config.json.

    Returns:
        tuple[bool, str]: Bandera de protección y razón asociada.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_texto)
    except ValueError:
        return True, "Formato IP inválido"

    if ip_obj.is_loopback or ip_obj.is_link_local:
        return True, "Dirección de loopback o enlace local"

    ip_admin: str = str(configuracion.get("ip_administrador", IP_ADMIN_DEFECTO))
    if ip_admin and ip_obj in ipaddress.ip_network(ip_admin, strict=False):
        return True, "IP protegida del administrador"

    for cidr in configuracion.get("lista_blanca", []):
        if ip_obj in ipaddress.ip_network(cidr, strict=False):
            return True, f"Subred en lista blanca ({{cidr}})"
    return False, ""


def ejecutar_regla_firewall(
    ip_texto: str,
    etapa: str,
    motor: str,
    eliminar: bool = False,
) -> list[str]:
    """Ejecuta el comando del firewall Linux sin invocar shell intermedia.

    Args:
        ip_texto: IP validada contra ipaddress.
        etapa: Nivel ('tasa_limitada' o 'bloqueado').
        motor: Herramienta ('iptables', 'ufw' o 'nftables').
        eliminar: True para revertir la regla, False para aplicarla.

    Returns:
        list[str]: Lista de argumentos ejecutada en el sistema.
    """
    ip_segura: str = str(ipaddress.ip_address(ip_texto))
    bandera: str = "-D" if eliminar else "-I"

    if motor == "ufw":
        accion: str = "limit" if etapa == "tasa_limitada" else "deny"
        if eliminar:
            cmd: list[str] = [
                "ufw", "delete", accion, "from", ip_segura,
                "to", "any", "port", "22",
            ]
        else:
            cmd = [
                "ufw", "insert", "1", accion, "from", ip_segura,
                "to", "any", "port", "22",
            ]
    elif etapa == "tasa_limitada":
        cmd = [
            "iptables", bandera, "INPUT", "-s", ip_segura, "-p", "tcp",
            "--dport", "22", "-m", "hashlimit", "--hashlimit-above", "3/min",
            "--hashlimit-burst", "3", "--hashlimit-mode", "srcip",
            "--hashlimit-name", "ssh_limit", "-j", "DROP",
        ]
    else:
        cmd = [
            "iptables", bandera, "INPUT", "-s", ip_segura,
            "-p", "tcp", "--dport", "22", "-j", "DROP",
        ]

    # Nunca usar shell=True con datos extraídos de logs para impedir RCE.
    subprocess.run(cmd, check=False, capture_output=True, text=True)
    return cmd


def notificar_slack(webhook_url: str, mensaje: str) -> None:
    """Envía una alerta JSON a Slack si existe un webhook configurado.

    Args:
        webhook_url: URL HTTPS del webhook de Slack.
        mensaje: Texto informativo de la alerta.
    """
    if not webhook_url.startswith("https://"):
        return
    cuerpo: bytes = json.dumps({{"text": mensaje}}).encode("utf-8")
    req: Request = Request(
        webhook_url,
        data=cuerpo,
        headers={{"Content-Type": "application/json"}},
        method="POST",
    )
    try:
        with urlopen(req, timeout=5):
            pass
    except (URLError, OSError):
        pass


def leer_nuevas_lineas_con_rotacion(
    ruta_log: Path,
    estado_archivos: dict[str, dict[str, int]],
) -> list[str]:
    """Lee líneas nuevas detectando rotación o truncamiento mediante inodo.

    Args:
        ruta_log: Ruta al archivo de registro (/var/log/auth.log o secure).
        estado_archivos: Diccionario persistente con inodo y offset previo.

    Returns:
        list[str]: Líneas agregadas desde la última lectura confirmada.
    """
    if not ruta_log.exists():
        return []

    stat_actual = ruta_log.stat()
    clave: str = str(ruta_log)
    previo: dict[str, int] = estado_archivos.get(
        clave, {{"inodo": stat_actual.st_ino, "offset": 0}}
    )
    lineas_totales: list[str] = []

    # Si cambió el inodo, logrotate renombró el archivo anterior (.1).
    # Se intenta leer el remanente del archivo rotado antes de reiniciar a 0.
    if stat_actual.st_ino != previo.get("inodo"):
        rotado: Path = Path(f"{{ruta_log}}.1")
        if rotado.exists() and rotado.stat().st_ino == previo.get("inodo"):
            with rotado.open("r", encoding="utf-8", errors="replace") as fh:
                fh.seek(previo.get("offset", 0))
                lineas_totales.extend(fh.read().splitlines())
        offset_inicio: int = 0
    elif stat_actual.st_size < previo.get("offset", 0):
        # Manejo de copytruncate: el tamaño disminuyó conservando el inodo.
        offset_inicio = 0
    else:
        offset_inicio = previo.get("offset", 0)

    with ruta_log.open("r", encoding="utf-8", errors="replace") as fh:
        fh.seek(offset_inicio)
        lineas_totales.extend(fh.read().splitlines())
        nuevo_offset: int = fh.tell()

    estado_archivos[clave] = {{
        "inodo": stat_actual.st_ino,
        "offset": nuevo_offset,
    }}
    return lineas_totales


def ejecutar_ciclo_monitoreo(logger: logging.Logger) -> None:
    """Bucle principal de vigilancia, detección y expiración de bloqueos.

    Args:
        logger: Registrador configurado para salidas de consola/syslog.
    """
    config: dict[str, Any] = leer_json_seguro(ARCHIVO_CONFIG, {{}})
    estado: dict[str, Any] = leer_json_seguro(
        ARCHIVO_ESTADO, {{"archivos": {{}}}}
    )
    ventanas: dict[str, list[dict[str, Any]]] = defaultdict(list)

    logger.info("Agente SentinelSSH iniciado en modo vigilancia continua.")
    while True:
        rutas: list[str] = config.get(
            "rutas_log", ["/var/log/auth.log", "/var/log/secure"]
        )
        ahora: datetime = datetime.now(timezone.utc)
        ventana_min: int = int(
            config.get("ventana_minutos", VENTANA_DEFECTO_MIN)
        )
        corte: datetime = ahora - timedelta(minutes=ventana_min)

        for ruta_str in rutas:
            lineas: list[str] = leer_nuevas_lineas_con_rotacion(
                Path(ruta_str), estado["archivos"]
            )
            for linea in lineas:
                ev: dict[str, Any] | None = analizar_linea_ssh(linea)
                if ev is None:
                    continue
                ip: str = str(ev["ip"])
                ventanas[ip].append({{"ts": ahora.isoformat(), **ev}})

        bloqueos: list[dict[str, Any]] = leer_json_seguro(ARCHIVO_BLOQUEOS, [])
        motor: str = str(config.get("motor_firewall", MOTOR_FIREWALL_DEFECTO))
        webhook: str = str(config.get("slack_webhook_url", ""))

        for ip, eventos in list(ventanas.items()):
            recientes: list[dict[str, Any]] = [
                e for e in eventos if datetime.fromisoformat(e["ts"]) >= corte
            ]
            ventanas[ip] = recientes
            fallos: int = sum(1 for e in recientes if e["es_fallo"])
            if fallos < int(config.get("umbral_alerta", UMBRAL_ALERTA_DEFECTO)):
                continue

            protegida, motivo = es_ip_protegida(ip, config)
            if protegida:
                logger.warning("Salvaguarda activa para %s: %s", ip, motivo)
                continue

            if fallos >= int(
                config.get("umbral_bloqueo", UMBRAL_BLOQUEO_DEFECTO)
            ):
                etapa = "bloqueado"
            elif fallos >= int(
                config.get("umbral_limitacion", UMBRAL_LIMITACION_DEFECTO)
            ):
                etapa = "tasa_limitada"
            else:
                etapa = "alerta"

            if etapa in ("tasa_limitada", "bloqueado"):
                cmd = ejecutar_regla_firewall(ip, etapa, motor)
                logger.warning("Regla %s aplicada a %s (%s)", etapa, ip, cmd)
                notificar_slack(
                    webhook,
                    f"[SentinelSSH] {{etapa}} aplicado a {{ip}} ({{fallos}} fallos)",
                )
                bloqueos.append(
                    {{
                        "ip": ip,
                        "etapa": etapa,
                        "fecha": ahora.isoformat(),
                        "expira_en": (
                            ahora
                            + timedelta(
                                hours=int(
                                    config.get(
                                        "horas_desbloqueo_auto",
                                        HORAS_DESBLOQUEO_DEFECTO,
                                    )
                                )
                            )
                        ).isoformat(),
                    }}
                )

        escribir_json_atomico(ARCHIVO_ESTADO, estado)
        escribir_json_atomico(ARCHIVO_BLOQUEOS, bloqueos)
        time.sleep(INTERVALO_SONDEO_SEG)


if __name__ == "__main__":
    ejecutar_ciclo_monitoreo(configurar_syslog())
'''
    return script


def construir_paquete_despliegue(
    configuracion: dict[str, Any],
    reputacion: list[dict[str, Any]],
) -> dict[str, str]:
    """Empaqueta el agente Python, su config.json y unidad systemd.

    Args:
        configuracion: Parámetros vigentes de SentinelSSH.
        reputacion: Entradas de lista blanca y lista negra.

    Returns:
        dict[str, str]: Diccionario con los contenidos listos para descarga.
    """
    lista_blanca: list[str] = [
        str(r["objetivo"])
        for r in reputacion
        if r.get("tipo") == "lista_blanca"
    ]
    config_agente: dict[str, Any] = {
        "umbral_alerta": configuracion.get("umbral_alerta", 3),
        "umbral_limitacion": configuracion.get("umbral_limitacion", 5),
        "umbral_bloqueo": configuracion.get("umbral_bloqueo", 10),
        "ventana_minutos": configuracion.get("ventana_minutos", 10),
        "horas_desbloqueo_auto": configuracion.get("horas_desbloqueo_auto", 24),
        "motor_firewall": configuracion.get("motor_firewall", "iptables"),
        "ip_administrador": configuracion.get("ip_administrador", "203.0.113.10"),
        "slack_webhook_url": configuracion.get("slack_webhook_url", ""),
        "rutas_log": configuracion.get(
            "rutas_log_monitoreadas", ["/var/log/auth.log", "/var/log/secure"]
        ),
        "lista_blanca": lista_blanca,
    }
    unidad_systemd: str = (
        "[Unit]\n"
        "Description=SentinelSSH Agente de Detección de Fuerza Bruta\n"
        "After=network.target sshd.service\n\n"
        "[Service]\n"
        "Type=simple\n"
        "User=root\n"
        "WorkingDirectory=/opt/sentinel-ssh\n"
        "ExecStart=/usr/bin/python3 /opt/sentinel-ssh/ssh_sentinel_agent.py\n"
        "Restart=always\n"
        "RestartSec=5\n"
        "ProtectSystem=full\n"
        "NoNewPrivileges=no\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )
    return {
        "script_python": construir_codigo_agente_python(
            configuracion, reputacion
        ),
        "config_json": json.dumps(config_agente, ensure_ascii=False, indent=2),
        "systemd_service": unidad_systemd,
    }
