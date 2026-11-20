import { Play, ShieldCheck, Upload } from 'lucide-react';
import { type ChangeEvent, useEffect, useState } from 'react';
import { analyzeLogs, runSimulation } from '../api';
import type { AnalyzeResult } from '../types';
import { StatusLabel } from './StatusLabel';

interface AnalyzerPanelProps {
  initialLogs: string;
  onClearInitialLogs: () => void;
  onRefresh: () => Promise<void>;
  onNotify: (kind: 'ok' | 'error', text: string) => void;
}

const SCENARIOS = [
  {
    id: 'fuerza_bruta',
    label: 'Fuerza bruta clásica',
    detail: '11 fallos rápidos contra root e inválidos',
  },
  {
    id: 'password_spray',
    label: 'Password spraying',
    detail: '6 usuarios distintos en RedHat/CentOS',
  },
  {
    id: 'error_usuario',
    label: 'Error de usuario legítimo',
    detail: '2 fallos + éxito final sin bloqueo',
  },
  {
    id: 'autobloqueo_admin',
    label: 'Prueba anti-autobloqueo',
    detail: '6 fallos desde IP del administrador',
  },
  {
    id: 'mixto_multidistro',
    label: 'Tráfico mixto Debian/RHEL',
    detail: 'Sondas pre-auth + acceso público válido',
  },
];

export function AnalyzerPanel({
  initialLogs,
  onClearInitialLogs,
  onRefresh,
  onNotify,
}: AnalyzerPanelProps) {
  const [logsText, setLogsText] = useState<string>('');
  const [sistema, setSistema] = useState<string>('auto');
  const [loading, setLoading] = useState<boolean>(false);
  const [result, setResult] = useState<AnalyzeResult | null>(null);
  const [activeScenarioDesc, setActiveScenarioDesc] = useState<string>('');

  useEffect(() => {
    if (initialLogs) {
      setLogsText(initialLogs);
      onClearInitialLogs();
    }
  }, [initialLogs, onClearInitialLogs]);

  const handleFileUpload = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      setLogsText(text);
      setActiveScenarioDesc(`Archivo cargado: ${file.name}`);
    } catch {
      onNotify('error', 'No se pudo leer el archivo seleccionado.');
    }
    event.target.value = '';
  };

  const handleAnalyze = async () => {
    if (!logsText.trim()) {
      onNotify('error', 'Pega líneas de registro SSH o sube un archivo primero.');
      return;
    }
    setLoading(true);
    try {
      const res = await analyzeLogs(logsText, sistema, 'carga_manual');
      setResult(res);
      await onRefresh();
      onNotify(
        'ok',
        `Se analizaron ${res.total_lineas_validas} eventos SSH (${res.escalamientos.length} mitigaciones activadas).`,
      );
    } catch (err) {
      onNotify(
        'error',
        err instanceof Error ? err.message : 'Error analizando registros.',
      );
    } finally {
      setLoading(false);
    }
  };

  const handleSimulate = async (scenarioId: string) => {
    setLoading(true);
    try {
      const sim = await runSimulation(scenarioId);
      setLogsText(sim.escenario.logs);
      setSistema(sim.escenario.sistema);
      setActiveScenarioDesc(
        `${sim.escenario.titulo}: ${sim.escenario.descripcion}`,
      );
      setResult(sim.resultado);
      await onRefresh();
      onNotify('ok', `Simulación ejecutada: ${sim.escenario.titulo}`);
    } catch (err) {
      onNotify(
        'error',
        err instanceof Error ? err.message : 'Error ejecutando simulación.',
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <section className="rounded-xl border border-slate-800/80 bg-[#0F172A] p-5">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h2 className="text-base font-semibold text-slate-100">
              Simulador de ataques y escenarios de prueba
            </h2>
            <p className="mt-0.5 text-xs text-slate-400">
              Genera registros realistas y comprueba cómo responde el motor en
              Python ante ataques o errores humanos
            </p>
          </div>
        </div>

        <div className="mt-4 grid grid-cols-1 gap-2.5 sm:grid-cols-2 lg:grid-cols-5">
          {SCENARIOS.map((sc) => (
            <button
              key={sc.id}
              type="button"
              disabled={loading}
              onClick={() => handleSimulate(sc.id)}
              className="flex flex-col items-start rounded-lg border border-slate-800 bg-[#0B1120] p-3 text-left transition-colors hover:border-sky-500/40 hover:bg-slate-900 disabled:opacity-50"
            >
              <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-sky-300">
                <Play className="h-3 w-3 shrink-0" />
                <span>{sc.label}</span>
              </span>
              <span className="mt-1 text-xs text-slate-400">{sc.detail}</span>
            </button>
          ))}
        </div>
      </section>

      <section className="rounded-xl border border-slate-800/80 bg-[#0F172A] p-5">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h2 className="text-base font-semibold text-slate-100">
              Analizador de logs reales (/var/log/auth.log y /var/log/secure)
            </h2>
            <p className="mt-0.5 text-xs text-slate-400">
              {activeScenarioDesc ||
                'Sube un archivo de registro Linux o pega líneas crudas de OpenSSH para extraer IP, usuario y estado'}
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <select
              value={sistema}
              onChange={(e) => setSistema(e.target.value)}
              aria-label="Formato de registro Linux"
              className="rounded-lg border border-slate-700 bg-[#0B1120] px-3 py-2 text-xs text-slate-200 focus:border-sky-400 focus:outline-none"
            >
              <option value="auto">Detección automática</option>
              <option value="debian_auth">/var/log/auth.log (Debian/Ubuntu)</option>
              <option value="redhat_secure">/var/log/secure (RedHat/CentOS)</option>
              <option value="journald">systemd / journald ISO-8601</option>
            </select>

            <label className="inline-flex cursor-pointer items-center gap-2 rounded-lg border border-slate-700 bg-[#0B1120] px-3.5 py-2 text-xs font-medium text-slate-200 transition-colors hover:bg-slate-800 whitespace-nowrap">
              <Upload className="h-3.5 w-3.5" />
              <span>Subir archivo .log</span>
              <input
                type="file"
                accept=".log,.txt,text/plain"
                onChange={handleFileUpload}
                className="sr-only"
              />
            </label>

            <button
              type="button"
              disabled={loading}
              onClick={handleAnalyze}
              className="rounded-lg bg-sky-500 px-4 py-2 text-xs font-semibold text-slate-950 transition-colors hover:bg-sky-400 disabled:opacity-50 whitespace-nowrap"
            >
              {loading ? 'Analizando...' : 'Analizar registros'}
            </button>
          </div>
        </div>

        <textarea
          value={logsText}
          onChange={(e) => setLogsText(e.target.value)}
          rows={7}
          spellCheck={false}
          placeholder="Nov 19 10:14:02 prod-web sshd[19201]: Failed password for invalid user admin from 198.51.100.88 port 53104 ssh2"
          className="mt-4 w-full rounded-lg border border-slate-800 bg-[#0B1120] p-3.5 font-mono text-xs leading-relaxed text-slate-200 placeholder:text-slate-600 focus:border-sky-400 focus:outline-none"
        />
      </section>

      {result && (
        <section className="space-y-4">
          {result.salvaguardas.length > 0 && (
            <div className="rounded-xl border border-sky-500/30 bg-sky-500/10 p-4">
              <div className="flex items-start gap-3">
                <ShieldCheck className="mt-0.5 h-5 w-5 shrink-0 text-sky-400" />
                <div>
                  <h3 className="text-sm font-semibold text-sky-200">
                    Salvaguarda anti-autobloqueo activada
                  </h3>
                  <ul className="mt-1 space-y-1 text-xs text-sky-100/90">
                    {result.salvaguardas.map((s) => (
                      <li key={s.ip}>
                        <span className="font-mono">{s.ip}</span> ({s.intentos}{' '}
                        intentos): {s.motivo}. No se aplicó bloqueo.
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          )}

          <div className="rounded-xl border border-slate-800/80 bg-[#0F172A]">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/80 px-5 py-3.5">
              <h3 className="text-sm font-semibold text-slate-100">
                Líneas extraídas por el parser ({result.total_lineas_validas})
              </h3>
              <span className="text-xs text-slate-400">
                Eventos nuevos persistidos: {result.eventos_nuevos} ·
                Escalamientos: {result.escalamientos.length}
              </span>
            </div>

            {result.eventos_analizados.length === 0 ? (
              <p className="px-5 py-8 text-center text-xs text-slate-400">
                Ninguna línea coincidió con los patrones OpenSSH esperados.
              </p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="border-b border-slate-800/80 text-slate-400">
                    <tr>
                      <th className="px-5 py-2.5 font-medium">Fecha UTC</th>
                      <th className="px-4 py-2.5 font-medium">IP Origen</th>
                      <th className="px-4 py-2.5 font-medium">Usuario</th>
                      <th className="px-4 py-2.5 font-medium">Sistema</th>
                      <th className="px-4 py-2.5 font-medium">Método</th>
                      <th className="px-5 py-2.5 font-medium">Resultado</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {result.eventos_analizados.map((ev) => (
                      <tr key={ev.id} className="hover:bg-slate-800/30">
                        <td className="px-5 py-2.5 font-mono text-slate-300 tabular-nums whitespace-nowrap">
                          {ev.fecha}
                        </td>
                        <td className="px-4 py-2.5 font-mono text-slate-100 tabular-nums whitespace-nowrap">
                          {ev.ip}
                        </td>
                        <td className="px-4 py-2.5 font-mono text-slate-200">
                          {ev.usuario}
                        </td>
                        <td className="px-4 py-2.5 text-slate-400 whitespace-nowrap">
                          {ev.sistema}
                        </td>
                        <td className="px-4 py-2.5 font-mono text-slate-400">
                          {ev.metodo}
                        </td>
                        <td className="px-5 py-2.5 whitespace-nowrap">
                          <StatusLabel estado={ev.estado} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </section>
      )}
    </div>
  );
}
