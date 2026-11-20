import type {
  AgentPackage,
  AnalyzeResult,
  DashboardData,
  DetectorConfig,
  LogSample,
  SimulationResponse,
} from './types';

async function requestJson<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers || {}),
    },
  });

  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(
      typeof payload?.error === 'string'
        ? payload.error
        : typeof payload?.mensaje === 'string'
          ? payload.mensaje
          : `Error HTTP ${response.status}`,
    );
  }
  return payload as T;
}

export function fetchDashboard(): Promise<DashboardData> {
  return requestJson<DashboardData>('/api/dashboard');
}

export function saveConfig(
  config: Partial<DetectorConfig>,
): Promise<{ ok: boolean; config: DetectorConfig }> {
  return requestJson('/api/config', {
    method: 'PUT',
    body: JSON.stringify(config),
  });
}

export function analyzeLogs(
  logs: string,
  sistema = 'auto',
  origen = 'carga_manual',
): Promise<AnalyzeResult> {
  return requestJson('/api/analyze', {
    method: 'POST',
    body: JSON.stringify({ logs, sistema, origen }),
  });
}

export function runSimulation(escenario: string): Promise<SimulationResponse> {
  return requestJson('/api/simulate', {
    method: 'POST',
    body: JSON.stringify({ escenario }),
  });
}

export function addReputationEntry(
  objetivo: string,
  tipo: 'lista_blanca' | 'lista_negra',
  etiqueta: string,
): Promise<{ ok: boolean }> {
  return requestJson('/api/reputation', {
    method: 'POST',
    body: JSON.stringify({ objetivo, tipo, etiqueta }),
  });
}

export function deleteReputationEntry(id: string): Promise<{ ok: boolean }> {
  return requestJson(`/api/reputation/${encodeURIComponent(id)}`, {
    method: 'DELETE',
  });
}

export function applyMitigationAction(
  ip: string,
  accion: 'desbloquear' | 'falso_positivo' | 'bloquear' | 'limitar',
  motivo = '',
): Promise<{ ok: boolean; mensaje: string }> {
  return requestJson('/api/mitigations/action', {
    method: 'POST',
    body: JSON.stringify({ ip, accion, motivo }),
  });
}

export function testSlackWebhook(
  webhookUrl: string,
): Promise<{ ok: boolean; mensaje: string }> {
  return requestJson('/api/slack/test', {
    method: 'POST',
    body: JSON.stringify({ webhook_url: webhookUrl }),
  });
}

export function fetchAgentPackage(): Promise<AgentPackage> {
  return requestJson('/api/agent/package');
}

export function fetchLogSamples(): Promise<{ muestras: LogSample[] }> {
  return requestJson('/api/samples');
}
