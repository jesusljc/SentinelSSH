# SentinelSSH

Plataforma de detección temprana, análisis forense y mitigación activa contra ataques de fuerza bruta sobre **SSH** en entornos Linux, acompañada de un panel web de monitoreo y un agente autónomo desplegable como servicio `systemd`.

## Características principales

- **Detección por ventana deslizante y ponderación de riesgo:** Correlaciona fallos de autenticación (`Failed password`, `Invalid user`, desconexiones prematuras) en `/var/log/auth.log` y `/var/log/secure`, aplicando mayor peso a intentos contra usuarios inexistentes.
- **Escalamiento progresivo de mitigación:** Clasifica cada IP atacante en cuatro estados según umbrales configurables: `observacion` → `alerta` → `tasa_limitada` → `bloqueado`, con desbloqueo automático por expiración temporal.
- **Protección anti-autobloqueo (Safeguards CIDR):** Impide bloquear la IP del administrador, rangos de red privada (`RFC 1918`) y subredes incluidas en la lista blanca antes de aplicar cualquier regla de firewall.
- **Generación de reglas de firewall y reputación IP:** Construye comandos listos para `iptables`, `nftables` o `ufw`, junto con puntuación de riesgo y seguimiento histórico por dirección origen.
- **Alertas en tiempo real por Slack:** Envía notificaciones estructuradas mediante *Incoming Webhooks* al alcanzar la etapa de escalamiento configurada.
- **Analizador y simulador de logs:** Permite auditar fragmentos reales de `sshd` o ejecutar ráfagas controladas de ataque para validar reglas y umbrales sin comprometer servidores en producción.
- **Agente Python independiente para Linux:** Genera y descarga el paquete listo para desplegar en `/opt/sentinel-ssh/` (`ssh_sentinel_agent.py`, `config.json` y `sentinel-ssh.service`) con manejo de rotación de logs por inodo y persistencia local en JSON.

## Arquitectura del proyecto

```text
SentinelSSH/
├── backend/                  # Motor de detección y API en Python (PEP 8)
│   ├── app.py                # Servidor HTTP y endpoints REST
│   ├── parser.py             # Extractor de eventos syslog / auth.log / secure
│   ├── detector.py           # Motor de correlación y ventana deslizante
│   ├── firewall.py           # Generador de reglas (iptables, nftables, ufw) y salvaguardas CIDR
│   ├── reputation.py         # Cálculo de reputación e historial por IP
│   ├── slack_notifier.py     # Integración con Webhooks de Slack
│   ├── agent_generator.py    # Constructor del agente Linux y unidad systemd
│   ├── samples.py            # Generador de escenarios y logs de prueba
│   ├── storage.py            # Persistencia atómica en archivos JSON
│   └── config.py             # Gestión de parámetros y umbrales
├── src/                      # Interfaz web en React + TypeScript + Vite
├── server.ts                 # Servidor proxy unificado (Node.js / Express)
├── data/                     # Configuración inicial y registros de auditoría
└── setup.cfg                 # Reglas de estilo PEP 8 (pycodestyle)
```

## Requisitos previos

- **Python 3.10+** (utiliza únicamente la biblioteca estándar para el motor y el agente).
- **Node.js 18+** y **npm**.

## Instalación y ejecución local

1. **Clonar el repositorio e instalar dependencias del frontend/proxy:**
   ```bash
   git clone https://github.com/jesusljc/SentinelSSH.git
   cd SentinelSSH
   npm install --legacy-peer-deps
   ```

2. **Configurar variables de entorno (opcional):**
   ```bash
   cp .env.example .env
   ```

3. **Iniciar el entorno unificado (backend Python + interfaz React):**
   ```bash
   npm run dev
   ```
   El panel estará disponible en `http://localhost:3000`.

## Despliegue del agente en Linux

Desde la sección **Agente Python y Guías** de la interfaz web podés descargar `ssh_sentinel_agent.py`, `config.json` y `sentinel-ssh.service` sincronizados con tus umbrales y lista blanca:

```bash
sudo mkdir -p /opt/sentinel-ssh
sudo cp ssh_sentinel_agent.py config.json /opt/sentinel-ssh/
sudo cp sentinel-ssh.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sentinel-ssh.service
```

## Calidad de código

El backend cumple con **PEP 8** (`max-line-length = 90` definido en `setup.cfg`):

```bash
pycodestyle backend/
python -m compileall backend/
```