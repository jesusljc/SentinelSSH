"""Servidor API REST en Python puro para SentinelSSH."""

from __future__ import annotations

import csv
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from typing import Any
from urllib.parse import parse_qs, urlparse

from backend.agent_generator import construir_paquete_despliegue
from backend.config import (
    ARCHIVO_ALERTAS,
    ARCHIVO_AUDITORIA,
    ARCHIVO_CONFIG,
    ARCHIVO_EVENTOS,
    ARCHIVO_MITIGACIONES,
    ARCHIVO_REPUTACION,
    MOTORES_FIREWALL_VALIDOS,
)
from backend.detector import MotorDetectorSSH
from backend.reputation import (
    crear_entrada_reputacion,
    validar_objetivo_ip_o_cidr,
)
from backend.samples import (
    generar_escenario_simulacion,
    obtener_muestras_documentacion,
)
from backend.slack_notifier import (
    construir_payload_slack,
    enviar_alerta_slack,
)
from backend.storage import AlmacenJson

HOST_SERVIDOR: str = "127.0.0.1"
PUERTO_SERVIDOR: int = int(os.environ.get("PYTHON_API_PORT", "8000"))

ALMACEN_GLOBAL: AlmacenJson = AlmacenJson()
MOTOR_GLOBAL: MotorDetectorSSH = MotorDetectorSSH(ALMACEN_GLOBAL)


def _construir_resumen(
    eventos: list[dict[str, Any]],
    mitigaciones: list[dict[str, Any]],
    auditoria: list[dict[str, Any]],
) -> dict[str, int]:
    """Calcula métricas agregadas reales a partir de los archivos JSON.

    Args:
        eventos: Eventos SSH almacenados.
        mitigaciones: Mitigaciones activas vigentes.
        auditoria: Historial de auditoría persistido.

    Returns:
        dict[str, int]: Contadores para el tablero principal.
    """
    fallos: int = sum(1 for ev in eventos if ev.get("es_fallo"))
    bloqueadas: int = sum(
        1 for m in mitigaciones if m.get("etapa") == "bloqueado"
    )
    limitadas: int = sum(
        1 for m in mitigaciones if m.get("etapa") == "tasa_limitada"
    )
    falsos_positivos: int = sum(
        1 for a in auditoria if a.get("tipo") == "falso_positivo"
    )
    return {
        "total_eventos": len(eventos),
        "intentos_fallidos": fallos,
        "ips_bloqueadas": bloqueadas,
        "ips_limitadas": limitadas,
        "falsos_positivos": falsos_positivos,
    }


def _generar_csv_auditoria(auditoria: list[dict[str, Any]]) -> str:
    """Serializa el registro de auditoría en formato CSV RFC 4180.

    Args:
        auditoria: Lista de eventos de auditoría almacenados.

    Returns:
        str: Contenido CSV con encabezados en español.
    """
    buffer: io.StringIO = io.StringIO()
    escritor = csv.writer(buffer)
    escritor.writerow(
        [
            "id", "fecha", "tipo", "ip", "etapa",
            "accion", "intentos", "usuarios", "detalle",
        ]
    )
    for fila in auditoria:
        usuarios_str: str = ";".join(fila.get("usuarios", []))
        escritor.writerow(
            [
                fila.get("id", ""),
                fila.get("fecha", ""),
                fila.get("tipo", ""),
                fila.get("ip", ""),
                fila.get("etapa", ""),
                fila.get("accion", ""),
                fila.get("intentos", 0),
                usuarios_str,
                fila.get("detalle", ""),
            ]
        )
    return buffer.getvalue()


class ManejadorApiSentinel(BaseHTTPRequestHandler):
    """Controlador HTTP REST para todas las operaciones de SentinelSSH."""

    def log_message(self, format: str, *args: Any) -> None:
        """Suprime logs verbosos por defecto de BaseHTTPRequestHandler."""
        return

    def _enviar_json(self, codigo: int, carga: Any) -> None:
        """Serializa y envía una respuesta HTTP con contenido JSON UTF-8.

        Args:
            codigo: Código de estado HTTP.
            carga: Estructura JSON a devolver al cliente.
        """
        cuerpo: bytes = json.dumps(carga, ensure_ascii=False).encode("utf-8")
        self.send_response(codigo)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(cuerpo)))
        self.end_headers()
        self.wfile.write(cuerpo)

    def _enviar_texto(
        self,
        codigo: int,
        contenido: str,
        tipo_mime: str,
        nombre_descarga: str = "",
    ) -> None:
        """Envía una respuesta de texto plano o descarga de archivo.

        Args:
            codigo: Código HTTP de respuesta.
            contenido: Texto UTF-8 a enviar.
            tipo_mime: Cabecera Content-Type correspondiente.
            nombre_descarga: Nombre sugerido para Content-Disposition.
        """
        cuerpo: bytes = contenido.encode("utf-8")
        self.send_response(codigo)
        self.send_header("Content-Type", f"{tipo_mime}; charset=utf-8")
        if nombre_descarga:
            self.send_header(
                "Content-Disposition",
                f'attachment; filename="{nombre_descarga}"',
            )
        self.send_header("Content-Length", str(len(cuerpo)))
        self.end_headers()
        self.wfile.write(cuerpo)

    def _leer_cuerpo_json(self) -> dict[str, Any]:
        """Lee y valida el cuerpo JSON de peticiones POST o PUT.

        Returns:
            dict[str, Any]: Diccionario decodificado desde la petición.

        Raises:
            ValueError: Si el cuerpo está vacío o contiene JSON inválido.
        """
        longitud: int = int(self.headers.get("Content-Length", "0"))
        if longitud <= 0 or longitud > 5_000_000:
            raise ValueError("Tamaño de petición inválido o vacío.")
        crudo: bytes = self.rfile.read(longitud)
        try:
            datos: Any = json.loads(crudo.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as err:
            raise ValueError(f"JSON inválido: {err}") from err
        if not isinstance(datos, dict):
            raise ValueError("Se esperaba un objeto JSON.")
        return datos

    def do_GET(self) -> None:
        """Atiende todas las rutas de consulta y exportación GET."""
        analizada = urlparse(self.path)
        ruta: str = analizada.path

        if ruta == "/api/health":
            self._enviar_json(
                200,
                {
                    "ok": True,
                    "motor": "python-3.11",
                    "almacen": "json-local",
                },
            )
            return

        if ruta == "/api/dashboard":
            mitigaciones = MOTOR_GLOBAL.limpiar_expiraciones()
            config = ALMACEN_GLOBAL.leer_json(ARCHIVO_CONFIG, {})
            reputacion = ALMACEN_GLOBAL.leer_json(ARCHIVO_REPUTACION, [])
            alertas = ALMACEN_GLOBAL.leer_json(ARCHIVO_ALERTAS, [])
            eventos = ALMACEN_GLOBAL.leer_json(ARCHIVO_EVENTOS, [])
            auditoria = ALMACEN_GLOBAL.leer_json(ARCHIVO_AUDITORIA, [])
            self._enviar_json(
                200,
                {
                    "config": config,
                    "reputacion": reputacion,
                    "mitigaciones": mitigaciones,
                    "alertas": alertas,
                    "eventos": eventos[:120],
                    "auditoria": auditoria[:200],
                    "resumen": _construir_resumen(
                        eventos, mitigaciones, auditoria
                    ),
                },
            )
            return

        if ruta == "/api/samples":
            self._enviar_json(
                200, {"muestras": obtener_muestras_documentacion()}
            )
            return

        if ruta == "/api/agent/package":
            config = ALMACEN_GLOBAL.leer_json(ARCHIVO_CONFIG, {})
            reputacion = ALMACEN_GLOBAL.leer_json(ARCHIVO_REPUTACION, [])
            paquete = construir_paquete_despliegue(config, reputacion)
            self._enviar_json(200, paquete)
            return

        if ruta == "/api/audit/export":
            parametros = parse_qs(analizada.query)
            formato: str = parametros.get("formato", ["json"])[0]
            auditoria = ALMACEN_GLOBAL.leer_json(ARCHIVO_AUDITORIA, [])
            if formato == "csv":
                self._enviar_texto(
                    200,
                    _generar_csv_auditoria(auditoria),
                    "text/csv",
                    "sentinel_ssh_auditoria.csv",
                )
            else:
                self._enviar_texto(
                    200,
                    json.dumps(auditoria, ensure_ascii=False, indent=2),
                    "application/json",
                    "sentinel_ssh_auditoria.json",
                )
            return

        self._enviar_json(404, {"error": f"Ruta no encontrada: {ruta}"})

    def do_PUT(self) -> None:
        """Atiende actualizaciones de configuración persistida en JSON."""
        ruta: str = urlparse(self.path).path
        if ruta != "/api/config":
            self._enviar_json(404, {"error": "Ruta no encontrada."})
            return

        try:
            datos = self._leer_cuerpo_json()
            config_actual: dict[str, Any] = ALMACEN_GLOBAL.leer_json(
                ARCHIVO_CONFIG, {}
            )
            motor: str = str(
                datos.get(
                    "motor_firewall",
                    config_actual.get("motor_firewall", "iptables"),
                )
            )
            if motor not in MOTORES_FIREWALL_VALIDOS:
                raise ValueError("Motor de firewall no válido.")

            ip_admin_raw: str = str(
                datos.get(
                    "ip_administrador",
                    config_actual.get("ip_administrador", "203.0.113.10"),
                )
            ).strip()
            if ip_admin_raw:
                validar_objetivo_ip_o_cidr(ip_admin_raw)

            nueva_config: dict[str, Any] = {
                **config_actual,
                "umbral_alerta": max(
                    1, int(datos.get("umbral_alerta", 3))
                ),
                "umbral_limitacion": max(
                    2, int(datos.get("umbral_limitacion", 5))
                ),
                "umbral_bloqueo": max(
                    3, int(datos.get("umbral_bloqueo", 10))
                ),
                "ventana_minutos": max(
                    1, min(120, int(datos.get("ventana_minutos", 10)))
                ),
                "peso_usuario_invalido": max(
                    1, min(5, int(datos.get("peso_usuario_invalido", 2)))
                ),
                "horas_desbloqueo_auto": max(
                    1, min(168, int(datos.get("horas_desbloqueo_auto", 24)))
                ),
                "motor_firewall": motor,
                "ip_administrador": ip_admin_raw,
                "proteger_redes_privadas": bool(
                    datos.get("proteger_redes_privadas", True)
                ),
                "slack_webhook_url": str(
                    datos.get("slack_webhook_url", "")
                ).strip(),
                "notificar_slack_en_etapa": str(
                    datos.get("notificar_slack_en_etapa", "tasa_limitada")
                ),
            }
            ALMACEN_GLOBAL.escribir_json(ARCHIVO_CONFIG, nueva_config)
            self._enviar_json(200, {"ok": True, "config": nueva_config})
        except ValueError as err:
            self._enviar_json(400, {"error": str(err)})

    def do_POST(self) -> None:
        """Atiende ingesta de logs, simulador, reputación, acciones y Slack."""
        ruta: str = urlparse(self.path).path
        try:
            datos = self._leer_cuerpo_json()
        except ValueError as err:
            self._enviar_json(400, {"error": str(err)})
            return

        if ruta == "/api/analyze":
            logs: str = str(datos.get("logs", ""))
            sistema: str = str(datos.get("sistema", "auto"))
            origen: str = str(datos.get("origen", "carga_manual"))
            if not logs.strip():
                self._enviar_json(
                    400, {"error": "Debes proporcionar líneas de registro SSH."}
                )
                return
            resultado = MOTOR_GLOBAL.procesar_texto_logs(
                logs, sistema_sugerido=sistema, origen_ingesta=origen
            )
            self._enviar_json(200, resultado)
            return

        if ruta == "/api/simulate":
            tipo: str = str(datos.get("escenario", "fuerza_bruta"))
            escenario = generar_escenario_simulacion(tipo)
            resultado = MOTOR_GLOBAL.procesar_texto_logs(
                escenario["logs"],
                sistema_sugerido=escenario["sistema"],
                origen_ingesta=f"simulador:{tipo}",
            )
            self._enviar_json(
                200, {"escenario": escenario, "resultado": resultado}
            )
            return

        if ruta == "/api/reputation":
            try:
                entrada = crear_entrada_reputacion(
                    objetivo=str(datos.get("objetivo", "")),
                    tipo=str(datos.get("tipo", "lista_blanca")),
                    etiqueta=str(datos.get("etiqueta", "")),
                    origen="manual",
                )
                reputacion: list[dict[str, Any]] = ALMACEN_GLOBAL.leer_json(
                    ARCHIVO_REPUTACION, []
                )
                reputacion.insert(0, entrada)
                ALMACEN_GLOBAL.escribir_json(ARCHIVO_REPUTACION, reputacion)
                self._enviar_json(201, {"ok": True, "entrada": entrada})
            except ValueError as err:
                self._enviar_json(400, {"error": str(err)})
            return

        if ruta == "/api/mitigations/action":
            try:
                res = MOTOR_GLOBAL.aplicar_accion_manual(
                    ip_objetivo=str(datos.get("ip", "")),
                    accion=str(datos.get("accion", "")),
                    motivo=str(datos.get("motivo", "")),
                )
                self._enviar_json(200, res)
            except ValueError as err:
                self._enviar_json(400, {"error": str(err)})
            return

        if ruta == "/api/slack/test":
            config = ALMACEN_GLOBAL.leer_json(ARCHIVO_CONFIG, {})
            url_usar: str = str(
                datos.get("webhook_url", "") or config.get(
                    "slack_webhook_url", "")
            ).strip()
            payload = construir_payload_slack(
                titulo="Prueba de integración Slack",
                ip_origen="198.51.100.1",
                etapa="alerta",
                intentos=3,
                usuarios=["root", "admin"],
                comando_firewall="# Prueba de conectividad desde SentinelSSH",
                detalle="Confirmación de recepción de alertas desde consola SOC.",
            )
            ok, mensaje = enviar_alerta_slack(url_usar, payload)
            auditoria: list[dict[str, Any]] = ALMACEN_GLOBAL.leer_json(
                ARCHIVO_AUDITORIA, []
            )
            auditoria.insert(
                0,
                {
                    "id": "aud-slack-test",
                    "fecha": payload["blocks"][0]["text"]["text"],
                    "tipo": "slack",
                    "ip": "webhook",
                    "etapa": "alerta",
                    "accion": (
                        "Prueba Slack exitosa" if ok else "Prueba Slack fallida"
                    ),
                    "detalle": mensaje,
                    "usuarios": [],
                    "intentos": 0,
                },
            )
            ALMACEN_GLOBAL.escribir_json(ARCHIVO_AUDITORIA, auditoria)
            self._enviar_json(200 if ok else 400, {
                              "ok": ok, "mensaje": mensaje})
            return

        self._enviar_json(404, {"error": f"Ruta no encontrada: {ruta}"})

    def do_DELETE(self) -> None:
        """Permite eliminar entradas manuales de reputación por identificador."""
        ruta: str = urlparse(self.path).path
        if not ruta.startswith("/api/reputation/"):
            self._enviar_json(404, {"error": "Ruta no encontrada."})
            return

        id_objetivo: str = ruta.removeprefix("/api/reputation/").strip()
        reputacion: list[dict[str, Any]] = ALMACEN_GLOBAL.leer_json(
            ARCHIVO_REPUTACION, []
        )
        nueva_lista: list[dict[str, Any]] = []
        eliminada: bool = False
        for item in reputacion:
            if item.get("id") == id_objetivo:
                if item.get("origen") == "sistema":
                    self._enviar_json(
                        400,
                        {
                            "error": (
                                "No se puede eliminar una red crítica del "
                                "sistema."
                            )
                        },
                    )
                    return
                eliminada = True
                continue
            nueva_lista.append(item)

        if not eliminada:
            self._enviar_json(404, {"error": "Entrada no encontrada."})
            return

        ALMACEN_GLOBAL.escribir_json(ARCHIVO_REPUTACION, nueva_lista)
        self._enviar_json(200, {"ok": True})


def iniciar_servidor() -> None:
    """Arranca el servidor HTTP Python multihilo en segundo plano."""
    servidor: ThreadingHTTPServer = ThreadingHTTPServer(
        (HOST_SERVIDOR, PUERTO_SERVIDOR),
        ManejadorApiSentinel,
    )
    print(
        f"Backend Python SentinelSSH activo en http://{HOST_SERVIDOR}:{PUERTO_SERVIDOR}",
        flush=True,
    )
    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        servidor.server_close()


if __name__ == "__main__":
    iniciar_servidor()
