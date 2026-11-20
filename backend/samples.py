"""Escenarios de simulación y muestras reales de registros SSH Linux."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any


def _marca_reciente(segundos_atras: int) -> str:
    """Genera una marca temporal ISO reciente para simulaciones coherentes.

    Args:
        segundos_atras: Desplazamiento hacia atrás desde el instante actual.

    Returns:
        str: Marca temporal ISO-8601 UTC.
    """
    instante: datetime = datetime.now(timezone.utc) - timedelta(
        seconds=segundos_atras
    )
    return instante.strftime("%Y-%m-%dT%H:%M:%SZ")


def generar_escenario_simulacion(tipo_escenario: str) -> dict[str, Any]:
    """Construye un bloque realista de registros SSH para un escenario dado.

    Args:
        tipo_escenario: Identificador ('fuerza_bruta', 'password_spray',
            'error_usuario', 'autobloqueo_admin' o 'mixto_multidistro').

    Returns:
        dict[str, Any]: Título, sistema sugerido, descripción y líneas de log.
    """
    if tipo_escenario == "fuerza_bruta":
        ip_atacante: str = "198.51.100.77"
        usuarios: list[str] = [
            "root",
            "root",
            "admin",
            "ubuntu",
            "postgres",
            "oracle",
            "test",
            "git",
            "deploy",
            "root",
            "root",
        ]
        lineas: list[str] = []
        for idx, usuario in enumerate(usuarios):
            ts: str = _marca_reciente(180 - idx * 12)
            if usuario in ("admin", "oracle", "test", "deploy"):
                lineas.append(
                    f"{ts} srv-prod-01 sshd[{4100 + idx}]: Failed password "
                    f"for invalid user {usuario} from {ip_atacante} "
                    f"port {51200 + idx} ssh2"
                )
            else:
                lineas.append(
                    f"{ts} srv-prod-01 sshd[{4100 + idx}]: Failed password "
                    f"for {usuario} from {ip_atacante} "
                    f"port {51200 + idx} ssh2"
                )
        return {
            "titulo": "Ataque de fuerza bruta clásico (Debian/Ubuntu)",
            "sistema": "debian_auth",
            "descripcion": (
                "11 intentos rápidos desde 198.51.100.77 combinando root y "
                "usuarios inválidos para disparar el bloqueo completo."
            ),
            "logs": "\n".join(lineas),
        }

    if tipo_escenario == "password_spray":
        ip_spray: str = "203.0.113.210"
        cuentas: list[str] = [
            "carlos",
            "lucia",
            "devops",
            "soporte",
            "backup",
            "ansible",
        ]
        lineas_spray: list[str] = [
            (
                f"{_marca_reciente(240 - idx * 25)} rhel-bastion-02 "
                f"sshd[{5200 + idx}]: Failed password for {cuenta} "
                f"from {ip_spray} port {44100 + idx} ssh2"
            )
            for idx, cuenta in enumerate(cuentas)
        ]
        return {
            "titulo": "Password spraying sobre cuentas válidas (RedHat/CentOS)",
            "sistema": "redhat_secure",
            "descripcion": (
                "6 cuentas distintas atacadas con una contraseña común desde "
                "203.0.113.210 para activar limitación de tasa."
            ),
            "logs": "\n".join(lineas_spray),
        }

    if tipo_escenario == "error_usuario":
        ip_legitima: str = "198.51.100.25"
        lineas_legit: list[str] = [
            (
                f"{_marca_reciente(95)} web-edge-01 sshd[6101]: "
                f"Failed password for mgarcia from {ip_legitima} "
                "port 55210 ssh2"
            ),
            (
                f"{_marca_reciente(80)} web-edge-01 sshd[6101]: "
                f"Failed password for mgarcia from {ip_legitima} "
                "port 55212 ssh2"
            ),
            (
                f"{_marca_reciente(64)} web-edge-01 sshd[6101]: "
                f"Accepted password for mgarcia from {ip_legitima} "
                "port 55214 ssh2"
            ),
        ]
        return {
            "titulo": "Error tipográfico de usuario legítimo",
            "sistema": "debian_auth",
            "descripcion": (
                "El usuario falla 2 veces y luego inicia sesión con éxito. "
                "El detector lo clasifica como error humano sin bloquear."
            ),
            "logs": "\n".join(lineas_legit),
        }

    if tipo_escenario == "autobloqueo_admin":
        ip_admin: str = "203.0.113.10"
        lineas_admin: list[str] = [
            (
                f"{_marca_reciente(120 - idx * 15)} bastion-01 sshd[{7000 + idx}]: "
                f"Failed password for sysadmin from {ip_admin} "
                f"port {60100 + idx} ssh2"
            )
            for idx in range(6)
        ]
        return {
            "titulo": "Prueba de salvaguarda anti-autobloqueo",
            "sistema": "debian_auth",
            "descripcion": (
                "Simula 6 fallos desde la IP protegida del administrador "
                "(203.0.113.10) para verificar que nunca sea bloqueada."
            ),
            "logs": "\n".join(lineas_admin),
        }

    # Escenario por defecto: mezcla realista multi-distro.
    return {
        "titulo": "Tráfico mixto multi-distro (Debian + RHEL)",
        "sistema": "auto",
        "descripcion": (
            "Combina ruido de escaneo pre-auth en Debian y fuerza bruta "
            "activa en RHEL."
        ),
        "logs": "\n".join(
            [
                (
                    f"{_marca_reciente(200)} ubuntu-db sshd[8110]: "
                    "Invalid user miner from 45.155.205.91 port 41022"
                ),
                (
                    f"{_marca_reciente(180)} ubuntu-db sshd[8112]: "
                    "Failed password for invalid user miner from "
                    "45.155.205.91 port 41024 ssh2"
                ),
                (
                    f"{_marca_reciente(160)} ubuntu-db sshd[8114]: "
                    "Failed password for invalid user admin from "
                    "45.155.205.91 port 41028 ssh2"
                ),
                (
                    f"{_marca_reciente(140)} rhel-api sshd[9020]: "
                    "Failed password for root from 45.155.205.91 "
                    "port 41030 ssh2"
                ),
                (
                    f"{_marca_reciente(120)} rhel-api sshd[9022]: "
                    "Disconnecting authenticating user root 45.155.205.91 "
                    "port 41030: Too many authentication failures [preauth]"
                ),
                (
                    f"{_marca_reciente(90)} rhel-api sshd[9025]: "
                    "Accepted publickey for deploy from 192.168.10.24 "
                    "port 52881 ssh2"
                ),
            ]
        ),
    }


def obtener_muestras_documentacion() -> list[dict[str, str]]:
    """Provee ejemplos reales anotados para entrenamiento y análisis rápido.

    Returns:
        list[dict[str, str]]: Lista de muestras con título, ruta Linux,
            explicación del patrón y líneas de ejemplo.
    """
    return [
        {
            "id": "muestra-debian",
            "titulo": "Ataque diccionario contra root y usuarios inválidos",
            "sistema": "debian_auth",
            "ruta_linux": "/var/log/auth.log (Debian / Ubuntu)",
            "explicacion": (
                "Obsérvese cómo OpenSSH antepone 'invalid user' cuando la "
                "cuenta no existe en /etc/passwd y registra la IP y puerto "
                "efímero de origen."
            ),
            "logs": (
                "Nov 19 10:14:02 prod-web sshd[19201]: Invalid user jenkins "
                "from 198.51.100.88 port 53104\n"
                "Nov 19 10:14:04 prod-web sshd[19201]: Failed password for "
                "invalid user jenkins from 198.51.100.88 port 53104 ssh2\n"
                "Nov 19 10:14:07 prod-web sshd[19204]: Failed password for "
                "root from 198.51.100.88 port 53118 ssh2\n"
                "Nov 19 10:14:09 prod-web sshd[19206]: Failed password for "
                "root from 198.51.100.88 port 53120 ssh2\n"
                "Nov 19 10:14:11 prod-web sshd[19208]: Failed password for "
                "invalid user postgres from 198.51.100.88 port 53125 ssh2\n"
                "Nov 19 10:14:13 prod-web sshd[19210]: Disconnecting "
                "authenticating user root 198.51.100.88 port 53129: "
                "Too many authentication failures [preauth]"
            ),
        },
        {
            "id": "muestra-rhel",
            "titulo": "Escaneo de fuerza bruta y cierre pre-autenticación",
            "sistema": "redhat_secure",
            "ruta_linux": "/var/log/secure (RedHat / CentOS / Rocky)",
            "explicacion": (
                "Incluye intentos de password fallidos junto con sondas "
                "de banner ('Did not receive identification string') típicas "
                "de escáneres masivos como Masscan o Shodan."
            ),
            "logs": (
                "Nov 19 11:02:10 rh-bastion sshd[3310]: Did not receive "
                "identification string from 203.0.113.144 port 38912\n"
                "Nov 19 11:02:14 rh-bastion sshd[3312]: Failed password for "
                "ec2-user from 203.0.113.144 port 38940 ssh2\n"
                "Nov 19 11:02:16 rh-bastion sshd[3314]: Failed password for "
                "centos from 203.0.113.144 port 38942 ssh2\n"
                "Nov 19 11:02:18 rh-bastion sshd[3316]: Failed password for "
                "invalid user oracle from 203.0.113.144 port 38945 ssh2\n"
                "Nov 19 11:02:21 rh-bastion sshd[3318]: Failed password for "
                "root from 203.0.113.144 port 38950 ssh2\n"
                "Nov 19 11:02:23 rh-bastion sshd[3320]: Connection closed by "
                "authenticating user root 203.0.113.144 port 38952 [preauth]"
            ),
        },
    ]
