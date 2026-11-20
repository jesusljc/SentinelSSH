export type FirewallEngine = 'iptables' | 'ufw' | 'nftables';

export type EscalationStage =
  | 'observacion'
  | 'alerta'
  | 'tasa_limitada'
  | 'bloqueado';

export type NavView =
  | 'monitoreo'
  | 'analizador'
  | 'reputacion'
  | 'auditoria'
  | 'agente';

export interface DetectorConfig {
  umbral_alerta: number;
  umbral_limitacion: number;
  umbral_bloqueo: number;
  ventana_minutos: number;
  peso_usuario_invalido: number;
  horas_desbloqueo_auto: number;
  motor_firewall: FirewallEngine;
  ip_administrador: string;
  proteger_redes_privadas: boolean;
  slack_webhook_url: string;
  notificar_slack_en_etapa: string;
  rutas_log_monitoreadas: string[];
}

export interface ReputationEntry {
  id: string;
  objetivo: string;
  tipo: 'lista_blanca' | 'lista_negra';
  etiqueta: string;
  protegida: boolean;
  origen: string;
  creado_en: string;
  incidentes: number;
}

export interface MitigationRecord {
  id: string;
  ip: string;
  etapa: EscalationStage;
  estado: string;
  motor_firewall: FirewallEngine;
  comando_firewall: string;
  intentos: number;
  puntaje_riesgo: number;
  usuarios: string[];
  origen_ingesta: string;
  actualizado_en: string;
  expira_en: string | null;
}

export interface AlertRecord {
  id: string;
  fecha: string;
  ip: string;
  etapa: EscalationStage;
  intentos: number;
  usuarios: string[];
  comando_firewall: string;
  mensaje: string;
  slack_enviado: boolean;
}

export interface LogEvent {
  id: string;
  fecha: string;
  host: string;
  sistema: string;
  ip: string;
  puerto: number;
  usuario: string;
  metodo: string;
  estado: string;
  es_fallo: boolean;
  linea_original: string;
}

export interface AuditRecord {
  id: string;
  fecha: string;
  tipo: string;
  ip: string;
  etapa: string;
  accion: string;
  detalle: string;
  usuarios: string[];
  intentos: number;
}

export interface DashboardSummary {
  total_eventos: number;
  intentos_fallidos: number;
  ips_bloqueadas: number;
  ips_limitadas: number;
  falsos_positivos: number;
}

export interface DashboardData {
  config: DetectorConfig;
  reputacion: ReputationEntry[];
  mitigaciones: MitigationRecord[];
  alertas: AlertRecord[];
  eventos: LogEvent[];
  auditoria: AuditRecord[];
  resumen: DashboardSummary;
}

export interface AnalyzeResult {
  total_lineas_validas: number;
  eventos_nuevos: number;
  eventos_analizados: LogEvent[];
  escalamientos: MitigationRecord[];
  salvaguardas: Array<{
    ip: string;
    motivo: string;
    intentos: number;
  }>;
}

export interface SimulationResponse {
  escenario: {
    titulo: string;
    sistema: string;
    descripcion: string;
    logs: string;
  };
  resultado: AnalyzeResult;
}

export interface AgentPackage {
  script_python: string;
  config_json: string;
  systemd_service: string;
}

export interface LogSample {
  id: string;
  titulo: string;
  sistema: string;
  ruta_linux: string;
  explicacion: string;
  logs: string;
}
