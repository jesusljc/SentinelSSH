import { ArrowRight, Check, RotateCcw, ShieldOff } from 'lucide-react';
import { useState } from 'react';
import { applyMitigationAction } from '../api';
import type { DashboardData, NavView } from '../types';
import { StatusLabel } from './StatusLabel';

interface OverviewPanelProps {
  data: DashboardData;
  onRefresh: () => Promise<void>;
  onNavigate: (view: NavView) => void;
  onNotify: (kind: 'ok' | 'error', text: string) => void;
}

function formatShortTime(iso: string | null): string {
  if (!iso) return 'Sin expiración';
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString('es-ES', {
    day: '2-digit',
    month: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function OverviewPanel({
  data,
  onRefresh,
  onNavigate,
  onNotify,
}: OverviewPanelProps) {
  const [busyIp, setBusyIp] = useState<string | null>(null);
  const [filterStage, setFilterStage] = useState<string>('todas');

  const handleAction = async (
    ip: string,
    accion: 'desbloquear' | 'falso_positivo',
  ) => {
    setBusyIp(ip);
    try {
      const res = await applyMitigationAction(
        ip,
        accion,
        accion === 'falso_positivo'
          ? 'Marcado desde resumen SOC como acceso legítimo'
          : 'Desbloqueo manual desde resumen SOC',
      );
      onNotify('ok', res.mensaje);
      await onRefresh();
    } catch (err) {
      onNotify(
        'error',
        err instanceof Error ? err.message : 'No se pudo ejecutar la acción.',
      );
    } finally {
      setBusyIp(null);
    }
  };

  const filteredMitigations = data.mitigaciones.filter((item) => {
    if (filterStage === 'todas') return true;
    return item.etapa === filterStage;
  });

  // Distribución simple por usuario objetivo para ayudar al analista a detectar patrones.
  const userCounts = new Map<string, number>();
  for (const ev of data.eventos) {
    if (ev.es_fallo) {
      userCounts.set(ev.usuario, (userCounts.get(ev.usuario) || 0) + 1);
    }
  }
  const topUsers = Array.from(userCounts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);
  const maxUserCount = topUsers[0]?.[1] || 1;

  return (
    <div className="space-y-6">
      <section className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <div className="rounded-xl border border-slate-800/80 bg-[#0F172A] p-5">
          <div className="text-xs font-medium text-slate-400">
            Intentos fallidos analizados
          </div>
          <div className="mt-2 font-mono text-3xl font-semibold tabular-nums text-slate-100">
            {data.resumen.intentos_fallidos}
          </div>
          <div className="mt-1 text-xs text-slate-500">
            De {data.resumen.total_eventos} eventos en logs
          </div>
        </div>

        <div className="rounded-xl border border-slate-800/80 bg-[#0F172A] p-5">
          <div className="text-xs font-medium text-slate-400">
            IPs bloqueadas (DROP)
          </div>
          <div className="mt-2 font-mono text-3xl font-semibold tabular-nums text-red-400">
            {data.resumen.ips_bloqueadas}
          </div>
          <div className="mt-1 text-xs text-slate-500">
            Expiración auto {data.config.horas_desbloqueo_auto} h
          </div>
        </div>

        <div className="rounded-xl border border-slate-800/80 bg-[#0F172A] p-5">
          <div className="text-xs font-medium text-slate-400">
            IPs con tasa limitada
          </div>
          <div className="mt-2 font-mono text-3xl font-semibold tabular-nums text-amber-400">
            {data.resumen.ips_limitadas}
          </div>
          <div className="mt-1 text-xs text-slate-500">
            Motor {data.config.motor_firewall}
          </div>
        </div>

        <div className="rounded-xl border border-slate-800/80 bg-[#0F172A] p-5">
          <div className="text-xs font-medium text-slate-400">
            Falsos positivos resueltos
          </div>
          <div className="mt-2 font-mono text-3xl font-semibold tabular-nums text-emerald-400">
            {data.resumen.falsos_positivos}
          </div>
          <div className="mt-1 text-xs text-slate-500">
            Movidos a lista blanca CIDR
          </div>
        </div>
      </section>

      <section className="rounded-xl border border-slate-800/80 bg-[#0F172A]">
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800/80 px-5 py-4">
          <div>
            <h2 className="text-base font-semibold text-slate-100">
              Mitigaciones activas y respuestas escalantes
            </h2>
            <p className="mt-0.5 text-xs text-slate-400">
              Ventana deslizante de {data.config.ventana_minutos} min · Alerta{' '}
              {data.config.umbral_alerta} · Limitación{' '}
              {data.config.umbral_limitacion} · Bloqueo{' '}
              {data.config.umbral_bloqueo}
            </p>
          </div>

          <div className="flex items-center gap-1 rounded-lg bg-[#0B1120] p-1">
            {[
              { id: 'todas', label: 'Todas' },
              { id: 'bloqueado', label: 'Bloqueadas' },
              { id: 'tasa_limitada', label: 'Limitadas' },
              { id: 'alerta', label: 'Alertas' },
            ].map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setFilterStage(tab.id)}
                className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                  filterStage === tab.id
                    ? 'bg-slate-800 text-slate-100'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        {filteredMitigations.length === 0 ? (
          <div className="flex flex-col items-center justify-center px-6 py-12 text-center">
            <p className="text-sm font-medium text-slate-200">
              No hay mitigaciones activas en esta vista
            </p>
            <p className="mt-1 max-w-md text-xs text-slate-400">
              Sube un archivo de registro SSH o ejecuta un escenario de ataque en
              el simulador para observar la detección en vivo.
            </p>
            <button
              type="button"
              onClick={() => onNavigate('analizador')}
              className="mt-4 inline-flex items-center gap-2 rounded-lg bg-sky-500 px-4 py-2 text-xs font-semibold text-slate-950 transition-colors hover:bg-sky-400 whitespace-nowrap"
            >
              <span>Abrir Analizador y Simulador</span>
              <ArrowRight className="h-3.5 w-3.5" />
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="border-b border-slate-800/80 text-xs text-slate-400">
                <tr>
                  <th className="px-5 py-3 font-medium">IP Origen</th>
                  <th className="px-4 py-3 font-medium">Estado</th>
                  <th className="px-4 py-3 text-right font-medium">Intentos</th>
                  <th className="px-4 py-3 font-medium">Usuarios objetivo</th>
                  <th className="px-4 py-3 font-medium">Regla generada</th>
                  <th className="px-4 py-3 font-medium">Expira</th>
                  <th className="px-5 py-3 text-right font-medium">Acciones</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredMitigations.map((item) => (
                  <tr
                    key={item.id}
                    className="transition-colors hover:bg-slate-800/30"
                  >
                    <td className="px-5 py-3 font-mono text-xs text-slate-100 tabular-nums whitespace-nowrap">
                      {item.ip}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <StatusLabel estado={item.etapa} />
                    </td>
                    <td className="px-4 py-3 text-right font-mono text-xs text-slate-200 tabular-nums">
                      {item.intentos}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-slate-300">
                      <span className="block max-w-[180px] truncate">
                        {item.usuarios.join(', ') || 'desconocido'}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-slate-400">
                      <span
                        className="block max-w-[260px] truncate"
                        title={item.comando_firewall}
                      >
                        {item.comando_firewall}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-slate-400 tabular-nums whitespace-nowrap">
                      {formatShortTime(item.expira_en)}
                    </td>
                    <td className="px-5 py-3 text-right whitespace-nowrap">
                      <div className="inline-flex items-center gap-2">
                        <button
                          type="button"
                          disabled={busyIp === item.ip}
                          onClick={() => handleAction(item.ip, 'desbloquear')}
                          className="inline-flex items-center gap-1 rounded-md border border-slate-700 px-2.5 py-1 text-xs font-medium text-slate-200 transition-colors hover:bg-slate-800 disabled:opacity-50"
                        >
                          <RotateCcw className="h-3 w-3" />
                          <span>Desbloquear</span>
                        </button>
                        <button
                          type="button"
                          disabled={busyIp === item.ip}
                          onClick={() =>
                            handleAction(item.ip, 'falso_positivo')
                          }
                          className="inline-flex items-center gap-1 rounded-md border border-emerald-500/30 px-2.5 py-1 text-xs font-medium text-emerald-300 transition-colors hover:bg-emerald-500/10 disabled:opacity-50"
                        >
                          <Check className="h-3 w-3" />
                          <span>Falso positivo</span>
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div className="rounded-xl border border-slate-800/80 bg-[#0F172A] p-5">
          <h3 className="text-sm font-semibold text-slate-100">
            Cuentas SSH más atacadas
          </h3>
          <p className="mt-0.5 text-xs text-slate-400">
            Frecuencia acumulada en los eventos analizados
          </p>

          {topUsers.length === 0 ? (
            <p className="mt-6 text-xs text-slate-500">
              Aún no hay intentos fallidos registrados.
            </p>
          ) : (
            <div className="mt-4 space-y-3">
              {topUsers.map(([usuario, count]) => (
                <div key={usuario} className="space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-mono text-slate-200">{usuario}</span>
                    <span className="font-mono tabular-nums text-slate-400">
                      {count} intentos
                    </span>
                  </div>
                  <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
                    <div
                      className="h-full rounded-full bg-sky-400"
                      style={{
                        width: `${Math.round((count / maxUserCount) * 100)}%`,
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="rounded-xl border border-slate-800/80 bg-[#0F172A] p-5">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-slate-100">
                Alertas recientes del detector
              </h3>
              <p className="mt-0.5 text-xs text-slate-400">
                Últimas transiciones hacia alerta, limitación o bloqueo
              </p>
            </div>
            <button
              type="button"
              onClick={() => onNavigate('auditoria')}
              className="text-xs font-medium text-sky-400 hover:underline whitespace-nowrap"
            >
              Ver auditoría
            </button>
          </div>

          {data.alertas.length === 0 ? (
            <div className="mt-6 flex items-center gap-2 text-xs text-slate-500">
              <ShieldOff className="h-4 w-4" />
              <span>Sin alertas disparadas hasta el momento.</span>
            </div>
          ) : (
            <div className="mt-4 divide-y divide-slate-800/60">
              {data.alertas.slice(0, 4).map((alerta) => (
                <div
                  key={alerta.id}
                  className="flex items-start justify-between gap-3 py-2.5 first:pt-0 last:pb-0"
                >
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 text-xs">
                      <span className="font-mono font-medium text-slate-100 tabular-nums">
                        {alerta.ip}
                      </span>
                      <span aria-hidden="true" className="text-slate-600">
                        ·
                      </span>
                      <StatusLabel estado={alerta.etapa} />
                    </div>
                    <p className="mt-1 truncate text-xs text-slate-400">
                      {alerta.mensaje}
                    </p>
                  </div>
                  <span className="font-mono text-xs text-slate-500 tabular-nums shrink-0">
                    {formatShortTime(alerta.fecha)}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </section>
    </div>
  );
}
