import { Menu, RefreshCw } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { fetchDashboard } from './api';
import { AgentDocsPanel } from './components/AgentDocsPanel';
import { AnalyzerPanel } from './components/AnalyzerPanel';
import { AuditSlackPanel } from './components/AuditSlackPanel';
import { OverviewPanel } from './components/OverviewPanel';
import { ReputationFirewallPanel } from './components/ReputationFirewallPanel';
import { Sidebar } from './components/Sidebar';
import type { DashboardData, NavView } from './types';

const VIEW_TITLES: Record<NavView, string> = {
  monitoreo: 'Monitoreo y Mitigaciones',
  analizador: 'Analizador de Logs y Simulador',
  reputacion: 'Reputación IP y Firewall',
  auditoria: 'Auditoría y Alertas Slack',
  agente: 'Agente Python y Documentación',
};

export default function App() {
  const [activeView, setActiveView] = useState<NavView>('monitoreo');
  const [mobileOpen, setMobileOpen] = useState<boolean>(false);
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string>('');
  const [toast, setToast] = useState<{ kind: 'ok' | 'error'; text: string } | null>(
    null,
  );
  const [queuedLogs, setQueuedLogs] = useState<string>('');

  const notify = useCallback((kind: 'ok' | 'error', text: string) => {
    setToast({ kind, text });
  }, []);

  useEffect(() => {
    if (!toast) return;
    const timer = window.setTimeout(() => setToast(null), 4500);
    return () => window.clearTimeout(timer);
  }, [toast]);

  const loadDashboard = useCallback(async () => {
    try {
      const next = await fetchDashboard();
      setData(next);
      setError('');
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : 'No se pudo conectar con el servidor Python.',
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadDashboard();
  }, [loadDashboard]);

  const handleLoadSampleInAnalyzer = useCallback((logs: string) => {
    setQueuedLogs(logs);
    setActiveView('analizador');
  }, []);

  const activeBlockCount = data?.resumen.ips_bloqueadas ?? 0;

  return (
    <div className="flex min-h-screen bg-[#0B1120] text-slate-100">
      <Sidebar
        activeView={activeView}
        onSelectView={setActiveView}
        mobileOpen={mobileOpen}
        onCloseMobile={() => setMobileOpen(false)}
        activeBlockCount={activeBlockCount}
      />

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-16 items-center justify-between gap-4 border-b border-slate-800/80 bg-[#0F172A]/80 px-6">
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              onClick={() => setMobileOpen(true)}
              className="rounded-md p-1.5 text-slate-400 hover:bg-slate-800 hover:text-slate-100 lg:hidden"
              aria-label="Abrir navegación"
            >
              <Menu className="h-5 w-5" />
            </button>
            <h1 className="truncate font-display text-lg font-semibold text-slate-100">
              {VIEW_TITLES[activeView]}
            </h1>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            <button
              type="button"
              onClick={loadDashboard}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 px-3 py-1.5 text-xs font-medium text-slate-200 transition-colors hover:bg-slate-800 whitespace-nowrap"
            >
              <RefreshCw className="h-3.5 w-3.5" />
              <span>Actualizar</span>
            </button>
            {activeView !== 'analizador' && (
              <button
                type="button"
                onClick={() => setActiveView('analizador')}
                className="rounded-lg bg-sky-500 px-3.5 py-1.5 text-xs font-semibold text-slate-950 transition-colors hover:bg-sky-400 whitespace-nowrap"
              >
                Probar ataque
              </button>
            )}
          </div>
        </header>

        <main className="mx-auto w-full max-w-[1240px] flex-1 p-6">
          {toast && (
            <div
              role="status"
              className={`mb-5 rounded-lg border px-4 py-2.5 text-xs font-medium ${
                toast.kind === 'ok'
                  ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                  : 'border-red-500/30 bg-red-500/10 text-red-300'
              }`}
            >
              {toast.text}
            </div>
          )}

          {loading ? (
            <div className="space-y-4">
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
                {[1, 2, 3, 4].map((n) => (
                  <div
                    key={n}
                    className="h-24 animate-pulse rounded-xl border border-slate-800/80 bg-[#0F172A]"
                  />
                ))}
              </div>
              <div className="h-64 animate-pulse rounded-xl border border-slate-800/80 bg-[#0F172A]" />
            </div>
          ) : error || !data ? (
            <div className="rounded-xl border border-red-500/30 bg-[#0F172A] p-6">
              <h2 className="text-base font-semibold text-red-300">
                Error conectando con el backend Python
              </h2>
              <p className="mt-1 text-xs text-slate-400">{error}</p>
              <button
                type="button"
                onClick={loadDashboard}
                className="mt-4 rounded-lg bg-sky-500 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-sky-400"
              >
                Reintentar conexión
              </button>
            </div>
          ) : (
            <>
              {activeView === 'monitoreo' && (
                <OverviewPanel
                  data={data}
                  onRefresh={loadDashboard}
                  onNavigate={setActiveView}
                  onNotify={notify}
                />
              )}
              {activeView === 'analizador' && (
                <AnalyzerPanel
                  initialLogs={queuedLogs}
                  onClearInitialLogs={() => setQueuedLogs('')}
                  onRefresh={loadDashboard}
                  onNotify={notify}
                />
              )}
              {activeView === 'reputacion' && (
                <ReputationFirewallPanel
                  config={data.config}
                  reputacion={data.reputacion}
                  onRefresh={loadDashboard}
                  onNotify={notify}
                />
              )}
              {activeView === 'auditoria' && (
                <AuditSlackPanel
                  config={data.config}
                  auditoria={data.auditoria}
                  onRefresh={loadDashboard}
                  onNotify={notify}
                />
              )}
              {activeView === 'agente' && (
                <AgentDocsPanel
                  onLoadSampleInAnalyzer={handleLoadSampleInAnalyzer}
                  onNotify={notify}
                />
              )}
            </>
          )}
        </main>
      </div>
    </div>
  );
}
