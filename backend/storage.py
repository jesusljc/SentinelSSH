"""Capa de persistencia local en archivos JSON atómicos."""

from __future__ import annotations

import json
import os
from pathlib import Path
import threading
from typing import Any

from backend.config import (
    ARCHIVO_ALERTAS,
    ARCHIVO_AUDITORIA,
    ARCHIVO_CONFIG,
    ARCHIVO_ESTADO_AGENTE,
    ARCHIVO_EVENTOS,
    ARCHIVO_MITIGACIONES,
    ARCHIVO_REPUTACION,
    DATA_DIR,
    obtener_configuracion_inicial,
    obtener_reputacion_inicial,
)


class AlmacenJson:
    """Gestor de lectura y escritura segura sobre archivos JSON en disco."""

    def __init__(self, directorio_datos: Path = DATA_DIR) -> None:
        """Inicializa el almacén y garantiza la estructura base en disco.

        Args:
            directorio_datos: Ruta donde residen los archivos JSON.
        """
        self._directorio: Path = directorio_datos
        # Bloqueo reentrante para serializar lecturas y escrituras concurrentes
        # desde hilos HTTP sin corromper los archivos JSON.
        self._bloqueo: threading.RLock = threading.RLock()
        self._directorio.mkdir(parents=True, exist_ok=True)
        self.asegurar_archivos_iniciales()

    def _ruta(self, nombre_archivo: str) -> Path:
        """Construye la ruta segura dentro del directorio de datos.

        Args:
            nombre_archivo: Nombre del archivo JSON objetivo.

        Returns:
            Path: Ruta absoluta validada dentro del directorio de datos.
        """
        nombre_limpio: str = Path(nombre_archivo).name
        return self._directorio / nombre_limpio

    def leer_json(self, nombre_archivo: str, defecto: Any) -> Any:
        """Lee y deserializa un archivo JSON devolviendo un valor seguro.

        Args:
            nombre_archivo: Archivo JSON a consultar.
            defecto: Valor de respaldo si el archivo no existe o es inválido.

        Returns:
            Any: Contenido deserializado del archivo JSON.
        """
        ruta: Path = self._ruta(nombre_archivo)
        with self._bloqueo:
            if not ruta.exists():
                return defecto
            try:
                contenido: str = ruta.read_text(encoding="utf-8")
                return json.loads(contenido)
            except (OSError, json.JSONDecodeError):
                return defecto

    def escribir_json(self, nombre_archivo: str, datos: Any) -> None:
        """Escribe datos en un archivo JSON mediante reemplazo atómico.

        Args:
            nombre_archivo: Archivo JSON destino.
            datos: Estructura serializable a guardar en disco.
        """
        ruta: Path = self._ruta(nombre_archivo)
        ruta_temporal: Path = ruta.with_suffix(".tmp")
        with self._bloqueo:
            texto: str = json.dumps(datos, ensure_ascii=False, indent=2)
            # Se escribe primero en un archivo temporal y luego se reemplaza
            # atómicamente para evitar archivos JSON truncados ante fallos.
            ruta_temporal.write_text(texto, encoding="utf-8")
            os.replace(ruta_temporal, ruta)

    def asegurar_archivos_iniciales(self) -> None:
        """Crea los archivos JSON necesarios si aún no existen en disco."""
        valores_base: list[tuple[str, Any]] = [
            (ARCHIVO_CONFIG, obtener_configuracion_inicial()),
            (ARCHIVO_REPUTACION, obtener_reputacion_inicial()),
            (ARCHIVO_EVENTOS, []),
            (ARCHIVO_MITIGACIONES, []),
            (ARCHIVO_ALERTAS, []),
            (ARCHIVO_AUDITORIA, []),
            (
                ARCHIVO_ESTADO_AGENTE,
                {
                    "archivos": {},
                    "ultima_ejecucion": None,
                    "lineas_procesadas_totales": 0,
                },
            ),
        ]
        with self._bloqueo:
            for nombre, valor_inicial in valores_base:
                ruta: Path = self._ruta(nombre)
                if not ruta.exists():
                    self.escribir_json(nombre, valor_inicial)
