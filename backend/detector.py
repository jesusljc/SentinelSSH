"""Motor de detección de fuerza bruta por ventana deslizante y escalamiento."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
import uuid

from backend.config import (
    ARCHIVO_ALERTAS,
    ARCHIVO_AUDITORIA,
    ARCHIVO_CONFIG,
    ARCHIVO_EVENTOS,
    ARCHIVO_MITIGACIONES,
    ARCHIVO_REPUTACION,
    MAX_ALERTAS_ALMACENADAS,
    MAX_AUDITORIA_ALMACENADA,
    MAX_EVENTOS_ALMACENADOS,
)
from backend.firewall import (
    calcular_expiracion_iso,
    generar_comando_desbloqueo,
    generar_comando_firewall,
    purgar_mitigaciones_expiradas,
)
from backend.parser import analizar_bloque_logs
from backend.reputation import (
    crear_entrada_reputacion,
    es_ip_protegida,
    esta_en_lista_negra,
)
from backend.slack_notifier import (
    construir_payload_slack,
    enviar_alerta_slack,
)
from backend.storage import AlmacenJson

JERARQUIA_ETAPAS: dict[str, int] = {
    "observacion": 0,
    "alerta": 1,
    "tasa_limitada": 2,
    "bloqueado": 3,
}


def _ahora_iso() -> str:
    """Devuelve la fecha y hora UTC actual en formato ISO-8601.

    Returns:
        str: Marca temporal UTC con sufijo Z.
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parsear_iso(fecha_str: str) -> datetime:
    """Convierte una cadena ISO-8601 a objeto datetime con zona horaria UTC.

    Args:
        fecha_str: Fecha ISO-8601 a interpretar.

    Returns:
        datetime: Instante convertido a UTC.
    """
    try:
        return datetime.fromisoformat(
            fecha_str.replace("Z", "+00:00")
        ).astimezone(timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def _registrar_auditoria(
    auditoria: list[dict[str, Any]],
    tipo: str,
    ip: str,
    etapa: str,
    accion: str,
    detalle: str,
    usuarios: list[str] | None = None,
    intentos: int = 0,
) -> None:
    """Agrega una entrada inmutable de auditoría al inicio del historial.

    Args:
        auditoria: Lista mutable de registros de auditoría.
        tipo: Categoría ('deteccion', 'bloqueo', 'desbloqueo',
            'falso_positivo', 'slack', 'salvaguarda').
        ip: Dirección IP relacionada.
        etapa: Etapa involucrada.
        accion: Resumen corto de la acción ejecutada.
        detalle: Explicación técnica del evento o motivo.
        usuarios: Lista de usuarios objetivo involucrados.
        intentos: Frecuencia de intentos registrada.
    """
    auditoria.insert(
        0,
        {
            "id": f"aud-{uuid.uuid4().hex[:8]}",
            "fecha": _ahora_iso(),
            "tipo": tipo,
            "ip": ip,
            "etapa": etapa,
            "accion": accion,
            "detalle": detalle,
            "usuarios": usuarios or [],
            "intentos": intentos,
        },
    )
    if len(auditoria) > MAX_AUDITORIA_ALMACENADA:
        del auditoria[MAX_AUDITORIA_ALMACENADA:]


def calcular_puntaje_riesgo_ip(
    eventos_ip: list[dict[str, Any]],
    configuracion: dict[str, Any],
    en_lista_negra: bool,
) -> dict[str, Any]:
    """Calcula intentos efectivos y clasifica si es error humano o ataque.

    Args:
        eventos_ip: Eventos recientes de la IP dentro de la ventana.
        configuracion: Umbrales y pesos configurados.
        en_lista_negra: Indica si la IP ya tiene reputación maliciosa previa.

    Returns:
        dict[str, Any]: Métricas de riesgo, clasificación y usuarios únicos.
    """
    fallos: int = 0
    invalidos: int = 0
    exitos: int = 0
    puntaje: int = 0
    usuarios: list[str] = []
    peso_invalido: int = int(configuracion.get("peso_usuario_invalido", 2))

    # Ordenar cronológicamente permite detectar si un usuario legítimo
    # falló 1-2 veces por error tipográfico y luego logró autenticarse.
    ordenados: list[dict[str, Any]] = sorted(
        eventos_ip, key=lambda ev: ev.get("fecha", "")
    )
    ultimo_es_exito: bool = False
    for evento in ordenados:
        usuario: str = str(evento.get("usuario", "desconocido"))
        if usuario not in usuarios:
            usuarios.append(usuario)
        estado: str = str(evento.get("estado", ""))
        if estado == "exitoso":
            exitos += 1
            ultimo_es_exito = True
        elif estado == "usuario_invalido":
            invalidos += 1
            puntaje += peso_invalido
            ultimo_es_exito = False
        elif evento.get("es_fallo"):
            fallos += 1
            puntaje += 1
            ultimo_es_exito = False

    if en_lista_negra and (fallos + invalidos) > 0:
        puntaje += int(configuracion.get("umbral_alerta", 3))

    # Si hubo pocos fallos y el último evento fue un login válido, se reduce
    # el puntaje para distinguir errores de tipeo humano de fuerza bruta real.
    es_error_usuario: bool = (
        ultimo_es_exito and (fallos + invalidos) <= 2 and invalidos == 0
    )
    if es_error_usuario:
        puntaje = 0

    return {
        "fallos_totales": fallos + invalidos,
        "usuarios_invalidos": invalidos,
        "exitos": exitos,
        "puntaje_efectivo": puntaje,
        "usuarios": usuarios,
        "clasificacion": (
            "error_usuario" if es_error_usuario else "sospechoso"
        ),
    }


def determinar_etapa_por_puntaje(
    puntaje: int,
    configuracion: dict[str, Any],
) -> str:
    """Mapea el puntaje de riesgo a la etapa de respuesta escalante.

    Args:
        puntaje: Puntaje efectivo calculado en la ventana temporal.
        configuracion: Umbrales de alerta, limitación y bloqueo.

    Returns:
        str: Etapa resultante ('observacion', 'alerta', 'tasa_limitada' o
            'bloqueado').
    """
    umbral_bloqueo: int = int(configuracion.get("umbral_bloqueo", 10))
    umbral_limitacion: int = int(configuracion.get("umbral_limitacion", 5))
    umbral_alerta: int = int(configuracion.get("umbral_alerta", 3))

    if puntaje >= umbral_bloqueo:
        return "bloqueado"
    if puntaje >= umbral_limitacion:
        return "tasa_limitada"
    if puntaje >= umbral_alerta:
        return "alerta"
    return "observacion"


class MotorDetectorSSH:
    """Orquestador principal de detección, reputación, firewall y auditoría."""

    def __init__(self, almacen: AlmacenJson) -> None:
        """Inicializa el motor con una instancia de almacén JSON.

        Args:
            almacen: Gestor de persistencia en archivos JSON locales.
        """
        self._almacen: AlmacenJson = almacen

    def limpiar_expiraciones(self) -> list[dict[str, Any]]:
        """Verifica y libera mitigaciones cuyo tiempo automático expiró.

        Returns:
            list[dict[str, Any]]: Lista actualizada de mitigaciones activas.
        """
        mitigaciones: list[dict[str, Any]] = self._almacen.leer_json(
            ARCHIVO_MITIGACIONES, []
        )
        activas, expiradas = purgar_mitigaciones_expiradas(mitigaciones)
        if expiradas:
            auditoria: list[dict[str, Any]] = self._almacen.leer_json(
                ARCHIVO_AUDITORIA, []
            )
            config: dict[str, Any] = self._almacen.leer_json(
                ARCHIVO_CONFIG, {}
            )
            motor: str = str(config.get("motor_firewall", "iptables"))
            for item in expiradas:
                cmd: str = generar_comando_desbloqueo(
                    str(item.get("ip", "")),
                    str(item.get("etapa", "bloqueado")),
                    motor,
                )
                _registrar_auditoria(
                    auditoria,
                    tipo="desbloqueo",
                    ip=str(item.get("ip", "")),
                    etapa="observacion",
                    accion="Desbloqueo automático por expiración",
                    detalle=f"Plazo cumplido. Regla revertida: {cmd}",
                    usuarios=item.get("usuarios", []),
                    intentos=int(item.get("intentos", 0)),
                )
            self._almacen.escribir_json(ARCHIVO_MITIGACIONES, activas)
            self._almacen.escribir_json(ARCHIVO_AUDITORIA, auditoria)
        return activas

    def procesar_texto_logs(
        self,
        texto_logs: str,
        sistema_sugerido: str = "auto",
        origen_ingesta: str = "manual",
    ) -> dict[str, Any]:
        """Analiza un lote de logs SSH, evalúa ventanas y ejecuta respuestas.

        Args:
            texto_logs: Contenido multilínea de registros SSH.
            sistema_sugerido: Formato esperado ('auto', 'debian_auth', etc.).
            origen_ingesta: Etiqueta del origen ('archivo', 'simulador', etc.).

        Returns:
            dict[str, Any]: Resumen con eventos extraídos, nuevas alertas y
                mitigaciones activadas o protegidas por salvaguardas.
        """
        self.limpiar_expiraciones()
        config: dict[str, Any] = self._almacen.leer_json(ARCHIVO_CONFIG, {})
        reputacion: list[dict[str, Any]] = self._almacen.leer_json(
            ARCHIVO_REPUTACION, []
        )
        eventos_guardados: list[dict[str, Any]] = self._almacen.leer_json(
            ARCHIVO_EVENTOS, []
        )
        mitigaciones: list[dict[str, Any]] = self._almacen.leer_json(
            ARCHIVO_MITIGACIONES, []
        )
        alertas: list[dict[str, Any]] = self._almacen.leer_json(
            ARCHIVO_ALERTAS, []
        )
        auditoria: list[dict[str, Any]] = self._almacen.leer_json(
            ARCHIVO_AUDITORIA, []
        )

        nuevos_eventos: list[dict[str, Any]] = analizar_bloque_logs(
            texto_logs, sistema_sugerido
        )
        hashes_existentes: set[str] = {
            str(ev.get("id", "")) for ev in eventos_guardados
        }
        eventos_agregados: list[dict[str, Any]] = []
        for ev in nuevos_eventos:
            if ev["id"] not in hashes_existentes:
                hashes_existentes.add(ev["id"])
                eventos_agregados.append(ev)

        combinados: list[dict[str, Any]
                         ] = eventos_agregados + eventos_guardados
        if len(combinados) > MAX_EVENTOS_ALMACENADOS:
            combinados = combinados[:MAX_EVENTOS_ALMACENADOS]

        ips_evaluadas: set[str] = {
            str(ev.get("ip", "")) for ev in nuevos_eventos if ev.get("ip")
        }
        mitigaciones_por_ip: dict[str, dict[str, Any]] = {
            str(m.get("ip", "")): m for m in mitigaciones
        }
        cambios_respuesta: list[dict[str, Any]] = []
        salvaguardas_activadas: list[dict[str, Any]] = []

        ventana_min: int = int(config.get("ventana_minutos", 10))
        motor_fw: str = str(config.get("motor_firewall", "iptables"))
        horas_exp: int = int(config.get("horas_desbloqueo_auto", 24))
        webhook_url: str = str(config.get("slack_webhook_url", "")).strip()
        etapa_slack: str = str(
            config.get("notificar_slack_en_etapa", "tasa_limitada")
        )

        for ip_origen in sorted(ips_evaluadas):
            eventos_ip: list[dict[str, Any]] = [
                ev for ev in combinados if ev.get("ip") == ip_origen
            ]
            # Tomar la referencia temporal del evento más reciente de la IP
            # para evaluar logs históricos o simulados con la misma precisión.
            fechas_ip: list[datetime] = [
                _parsear_iso(str(ev.get("fecha", ""))) for ev in eventos_ip
            ]
            marca_max: datetime = max(fechas_ip) if fechas_ip else datetime.now(
                timezone.utc
            )
            corte_ventana: datetime = marca_max - timedelta(
                minutes=ventana_min
            )
            en_ventana: list[dict[str, Any]] = [
                ev
                for ev in eventos_ip
                if _parsear_iso(str(ev.get("fecha", ""))) >= corte_ventana
            ]

            entrada_mala: dict[str, Any] | None = esta_en_lista_negra(
                ip_origen, reputacion
            )
            metricas: dict[str, Any] = calcular_puntaje_riesgo_ip(
                en_ventana, config, entrada_mala is not None
            )
            etapa_nueva: str = determinar_etapa_por_puntaje(
                int(metricas["puntaje_efectivo"]), config
            )

            protegida, motivo_prot = es_ip_protegida(
                ip_origen, config, reputacion
            )
            if protegida:
                if int(metricas["fallos_totales"]) >= int(
                    config.get("umbral_alerta", 3)
                ):
                    aviso: dict[str, Any] = {
                        "ip": ip_origen,
                        "motivo": motivo_prot,
                        "intentos": metricas["fallos_totales"],
                    }
                    salvaguardas_activadas.append(aviso)
                    _registrar_auditoria(
                        auditoria,
                        tipo="salvaguarda",
                        ip=ip_origen,
                        etapa="observacion",
                        accion="Bloqueo prevenido por salvaguarda",
                        detalle=motivo_prot,
                        usuarios=metricas["usuarios"],
                        intentos=int(metricas["fallos_totales"]),
                    )
                continue

            if etapa_nueva == "observacion":
                continue

            existente: dict[str, Any] | None = mitigaciones_por_ip.get(
                ip_origen
            )
            nivel_previo: int = (
                JERARQUIA_ETAPAS.get(str(existente.get("etapa", "")), 0)
                if existente
                else 0
            )
            nivel_nuevo: int = JERARQUIA_ETAPAS.get(etapa_nueva, 0)

            comando_fw: str = generar_comando_firewall(
                ip_origen, etapa_nueva, motor_fw
            )
            registro_mitigacion: dict[str, Any] = {
                "id": existente["id"] if existente else f"mit-{uuid.uuid4().hex[:8]}",
                "ip": ip_origen,
                "etapa": (
                    etapa_nueva
                    if nivel_nuevo >= nivel_previo
                    else str(existente["etapa"])
                ),
                "estado": "activa",
                "motor_firewall": motor_fw,
                "comando_firewall": comando_fw,
                "intentos": int(metricas["fallos_totales"]),
                "puntaje_riesgo": int(metricas["puntaje_efectivo"]),
                "usuarios": metricas["usuarios"],
                "origen_ingesta": origen_ingesta,
                "actualizado_en": _ahora_iso(),
                "expira_en": (
                    calcular_expiracion_iso(horas_exp)
                    if etapa_nueva in ("tasa_limitada", "bloqueado")
                    else None
                ),
            }
            mitigaciones_por_ip[ip_origen] = registro_mitigacion

            if nivel_nuevo > nivel_previo:
                cambios_respuesta.append(registro_mitigacion)
                alerta_item: dict[str, Any] = {
                    "id": f"alt-{uuid.uuid4().hex[:8]}",
                    "fecha": _ahora_iso(),
                    "ip": ip_origen,
                    "etapa": etapa_nueva,
                    "intentos": int(metricas["fallos_totales"]),
                    "usuarios": metricas["usuarios"],
                    "comando_firewall": comando_fw,
                    "mensaje": (
                        f"Escalamiento a {etapa_nueva} tras "
                        f"{metricas['fallos_totales']} fallos en "
                        f"{ventana_min} min."
                    ),
                    "slack_enviado": False,
                }
                if (
                    webhook_url
                    and JERARQUIA_ETAPAS.get(etapa_nueva, 0)
                    >= JERARQUIA_ETAPAS.get(etapa_slack, 2)
                ):
                    payload = construir_payload_slack(
                        titulo=f"Respuesta SSH: {etapa_nueva}",
                        ip_origen=ip_origen,
                        etapa=etapa_nueva,
                        intentos=int(metricas["fallos_totales"]),
                        usuarios=metricas["usuarios"],
                        comando_firewall=comando_fw,
                        detalle=alerta_item["mensaje"],
                    )
                    ok_slack, msg_slack = enviar_alerta_slack(
                        webhook_url, payload
                    )
                    alerta_item["slack_enviado"] = ok_slack
                    _registrar_auditoria(
                        auditoria,
                        tipo="slack",
                        ip=ip_origen,
                        etapa=etapa_nueva,
                        accion=(
                            "Notificación Slack enviada"
                            if ok_slack
                            else "Fallo al enviar a Slack"
                        ),
                        detalle=msg_slack,
                        usuarios=metricas["usuarios"],
                        intentos=int(metricas["fallos_totales"]),
                    )

                alertas.insert(0, alerta_item)
                if len(alertas) > MAX_ALERTAS_ALMACENADAS:
                    del alertas[MAX_ALERTAS_ALMACENADAS:]

                _registrar_auditoria(
                    auditoria,
                    tipo="bloqueo" if etapa_nueva == "bloqueado" else "deteccion",
                    ip=ip_origen,
                    etapa=etapa_nueva,
                    accion=f"Respuesta escalante: {etapa_nueva}",
                    detalle=(
                        f"Origen: {origen_ingesta}. Comando: {comando_fw}"
                    ),
                    usuarios=metricas["usuarios"],
                    intentos=int(metricas["fallos_totales"]),
                )

                if etapa_nueva == "bloqueado" and entrada_mala is None:
                    reputacion.insert(
                        0,
                        crear_entrada_reputacion(
                            objetivo=f"{ip_origen}/32",
                            tipo="lista_negra",
                            etiqueta=(
                                f"Fuerza bruta SSH ({metricas['fallos_totales']}"
                                " intentos)"
                            ),
                            origen="deteccion",
                        ),
                    )

        mitigaciones_actualizadas: list[dict[str, Any]] = list(
            mitigaciones_por_ip.values()
        )
        self._almacen.escribir_json(ARCHIVO_EVENTOS, combinados)
        self._almacen.escribir_json(
            ARCHIVO_MITIGACIONES, mitigaciones_actualizadas
        )
        self._almacen.escribir_json(ARCHIVO_ALERTAS, alertas)
        self._almacen.escribir_json(ARCHIVO_AUDITORIA, auditoria)
        self._almacen.escribir_json(ARCHIVO_REPUTACION, reputacion)

        return {
            "total_lineas_validas": len(nuevos_eventos),
            "eventos_nuevos": len(eventos_agregados),
            "eventos_analizados": nuevos_eventos[:80],
            "escalamientos": cambios_respuesta,
            "salvaguardas": salvaguardas_activadas,
        }

    def aplicar_accion_manual(
        self,
        ip_objetivo: str,
        accion: str,
        motivo: str = "",
    ) -> dict[str, Any]:
        """Ejecuta desbloqueo manual, bloqueo forzado o falso positivo.

        Args:
            ip_objetivo: Dirección IP sobre la cual operar.
            accion: Acción solicitada ('desbloquear', 'falso_positivo',
                'bloquear' o 'limitar').
            motivo: Nota explicativa opcional para auditoría.

        Returns:
            dict[str, Any]: Resultado de la operación y estado actualizado.

        Raises:
            ValueError: Si la acción viola una salvaguarda anti-autobloqueo.
        """
        config: dict[str, Any] = self._almacen.leer_json(ARCHIVO_CONFIG, {})
        reputacion: list[dict[str, Any]] = self._almacen.leer_json(
            ARCHIVO_REPUTACION, []
        )
        mitigaciones: list[dict[str, Any]] = self._almacen.leer_json(
            ARCHIVO_MITIGACIONES, []
        )
        auditoria: list[dict[str, Any]] = self._almacen.leer_json(
            ARCHIVO_AUDITORIA, []
        )
        motor_fw: str = str(config.get("motor_firewall", "iptables"))
        ip_limpia: str = ip_objetivo.strip()

        if accion in ("bloquear", "limitar"):
            protegida, motivo_prot = es_ip_protegida(
                ip_limpia, config, reputacion
            )
            if protegida:
                _registrar_auditoria(
                    auditoria,
                    tipo="salvaguarda",
                    ip=ip_limpia,
                    etapa="observacion",
                    accion="Acción manual rechazada por salvaguarda",
                    detalle=motivo_prot,
                )
                self._almacen.escribir_json(ARCHIVO_AUDITORIA, auditoria)
                raise ValueError(
                    f"Salvaguarda anti-autobloqueo activada: {motivo_prot}"
                )

            etapa: str = (
                "bloqueado" if accion == "bloquear" else "tasa_limitada"
            )
            cmd: str = generar_comando_firewall(ip_limpia, etapa, motor_fw)
            horas_exp: int = int(config.get("horas_desbloqueo_auto", 24))
            mitigaciones = [
                m for m in mitigaciones if m.get("ip") != ip_limpia]
            mitigaciones.insert(
                0,
                {
                    "id": f"mit-{uuid.uuid4().hex[:8]}",
                    "ip": ip_limpia,
                    "etapa": etapa,
                    "estado": "activa",
                    "motor_firewall": motor_fw,
                    "comando_firewall": cmd,
                    "intentos": 1,
                    "puntaje_riesgo": 10 if etapa == "bloqueado" else 5,
                    "usuarios": ["manual"],
                    "origen_ingesta": "accion_manual",
                    "actualizado_en": _ahora_iso(),
                    "expira_en": calcular_expiracion_iso(horas_exp),
                },
            )
            _registrar_auditoria(
                auditoria,
                tipo="bloqueo",
                ip=ip_limpia,
                etapa=etapa,
                accion=f"Acción manual aplicada: {etapa}",
                detalle=motivo or cmd,
            )
            self._almacen.escribir_json(ARCHIVO_MITIGACIONES, mitigaciones)
            self._almacen.escribir_json(ARCHIVO_AUDITORIA, auditoria)
            return {"ok": True, "mensaje": f"Regla {etapa} aplicada a {ip_limpia}."}

        if accion in ("desbloquear", "falso_positivo"):
            restantes: list[dict[str, Any]] = []
            eliminada: dict[str, Any] | None = None
            for item in mitigaciones:
                if item.get("ip") == ip_limpia:
                    eliminada = item
                else:
                    restantes.append(item)

            etapa_previa: str = (
                str(eliminada.get("etapa", "bloqueado"))
                if eliminada
                else "bloqueado"
            )
            cmd_des: str = generar_comando_desbloqueo(
                ip_limpia, etapa_previa, motor_fw
            )
            if accion == "falso_positivo":
                reputacion = [
                    r
                    for r in reputacion
                    if r.get("objetivo") != f"{ip_limpia}/32"
                ]
                reputacion.insert(
                    0,
                    crear_entrada_reputacion(
                        objetivo=f"{ip_limpia}/32",
                        tipo="lista_blanca",
                        etiqueta=motivo or "Falso positivo confirmado por SOC",
                        origen="falso_positivo",
                    ),
                )
                _registrar_auditoria(
                    auditoria,
                    tipo="falso_positivo",
                    ip=ip_limpia,
                    etapa="observacion",
                    accion="Marcada como falso positivo y movida a lista blanca",
                    detalle=f"Regla revertida: {cmd_des}",
                    usuarios=eliminada.get(
                        "usuarios", []) if eliminada else [],
                    intentos=int(eliminada.get("intentos", 0)
                                 ) if eliminada else 0,
                )
            else:
                _registrar_auditoria(
                    auditoria,
                    tipo="desbloqueo",
                    ip=ip_limpia,
                    etapa="observacion",
                    accion="Desbloqueo manual ejecutado",
                    detalle=motivo or f"Regla revertida: {cmd_des}",
                    usuarios=eliminada.get(
                        "usuarios", []) if eliminada else [],
                    intentos=int(eliminada.get("intentos", 0)
                                 ) if eliminada else 0,
                )

            self._almacen.escribir_json(ARCHIVO_MITIGACIONES, restantes)
            self._almacen.escribir_json(ARCHIVO_REPUTACION, reputacion)
            self._almacen.escribir_json(ARCHIVO_AUDITORIA, auditoria)
            return {
                "ok": True,
                "mensaje": f"IP {ip_limpia} liberada correctamente.",
            }

        raise ValueError(f"Acción no soportada: {accion}")
