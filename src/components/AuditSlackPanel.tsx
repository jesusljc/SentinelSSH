import { Download, Search, Send } from 'lucide-react';
import { type FormEvent, useEffect, useState } from 'react';
import { saveConfig, testSlackWebhook } from '../api';
import type { AuditRecord, DetectorConfig } from '../types';
import { StatusLabel } from './StatusLabel';

interface AuditSlackPanelProps {
  config: DetectorConfig;
  auditoria: AuditRecord[];
  onRefresh: () => Promise<void>;
  onNotify: (kind: 'ok' | 'error', text: string) => void;
}

const AUDIT_FILTERS = [
  { id: 'todos', label: 'Todos' },
  { id: 'bloqueo', label: 'Bloqueos' },
  { id: 'deteccion', label: 'Detecciones' },
  { id: 'desbloqueo', label: 'Desbloqueos' },
  { id: 'falso_positivo', label: 'Falsos positivos' },
  { id: 'salvaguarda', label: 'Salvaguardas' },
  { id: 'slack', label: 'Slack' },
];

export function AuditSlackPanel({
  config,
  auditoria,
  onRefresh,
  onNotify,
}: AuditSlackPanelProps) {
  const [webhookUrl, setWebhookUrl] = useState<string>(config.slack_webhook_url);
  const [notifyStage, setNotifyStage] = useState<string>(
    config.notificar_slack_en_etapa || 'tasa_limitada',
  );
  const [saving, setSaving] = useState<boolean>(false);
  const [testing, setTesting] = useState<boolean>(false);
  const [filterType, setFilterType] = useState<string>('todos');
  const [query, setQuery] = useState<string>('');

  useEffect(() => {
    setWebhookUrl(config.slack_webhook_url);
    setNotifyStage(config.notificar_slack_en_etapa || 'tasa_limitada');
  }, [config]);

  const handleSaveSlack = async (e: FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      await saveConfig({
        ...config,
        slack_webhook_url: webhookUrl,
        notificar_slack_en_etapa: notifyStage,
      });
      await onRefresh();
      onNotify('ok', 'Configuración de Slack guardada en data/config.json.');
    } catch (err) {
      onNotify(
        'error',
        err instanceof Error ? err.message : 'Error guardando webhook.',
      );
    } finally {
      setSaving(false);
    }
  };

  const handleTestSlack = async () => {
    setTesting(true);
    try {
      const res = await testSlackWebhook(webhookUrl);
      await onRefresh();
      onNotify('ok', res.mensaje);
    } catch (err) {
      await onRefresh();
      onNotify(
        'error',
        err instanceof Error ? err.message : 'Falló la prueba del webhook.',
      );
    } finally {
      setTesting(false);
    }
  };

  const filteredAudit = auditoria.filter((item) => {
    if (filterType !== 'todos' && item.tipo !== filterType) return false;
    if (!query.trim()) return true;
    const q = query.toLowerCase();
    return (
      item.ip.toLowerCase().includes(q) ||
      item.accion.toLowerCase().includes(q) ||
      item.detalle.toLowerCase().includes(q) ||
      item.usuarios.some((u) => u.toLowerCase().includes(q))
    );
  });

  return (
    <div className="space-y-6">
      <form
        onSubmit={handleSaveSlack}
        className="rounded-xl border border-slate-800/80 bg-[#0F172A] p-5"
      >
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
          <div>
            <h2 className="text-base font-semibold text-slate-100">
              Integración de alertas con Slack Webhook
            </h2>
            <p className="mt-0.5 text-xs text-slate-400">
              El servidor Python despacha alertas reales por HTTPS sin exponer
              tu URL en el navegador
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              disabled={testing}
              onClick={handleTestSlack}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 px-3.5 py-2 text-xs font-medium text-slate-200 hover:bg-slate-800 disabled:opacity-50 whitespace-nowrap"
            >
              <Send className="h-3.5 w-3.5" />
              <span>{testing ? 'Enviando...' : 'Probar webhook'}</span>
            </button>
            <button
              type="submit"
              disabled={saving}
              className="rounded-lg bg-sky-500 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-sky-400 disabled:opacity-50 whitespace-nowrap"
            >
              {saving ? 'Guardando...' : 'Guardar'}
            </button>
          </div>
        </div>

        <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-12">
          <label className="block space-y-1.5 text-xs lg:col-span-8">
            <span className="font-medium text-slate-300">
              URL de Incoming Webhook de Slack
            </span>
            <input
              type="url"
              value={webhookUrl}
              onChange={(e) => setWebhookUrl(e.target.value)}
              placeholder="https://hooks.slack.com/services/T000000/B000000/XXXXXXXX"
              className="w-full rounded-lg border border-slate-700 bg-[#0B1120] px-3 py-2 font-mono text-xs text-slate-100 placeholder:text-slate-600 focus:border-sky-400 focus:outline-none"
            />
          </label>

          <label className="block space-y-1.5 text-xs lg:col-span-4">
            <span className="font-medium text-slate-300">
              Notificar automáticamente desde etapa
            </span>
            <select
              value={notifyStage}
              onChange={(e) => setNotifyStage(e.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-[#0B1120] px-3 py-2 text-xs text-slate-100 focus:border-sky-400 focus:outline-none"
            >
              <option value="alerta">Etapa 1: Alerta temprana</option>
              <option value="tasa_limitada">Etapa 2: Limitación de tasa</option>
              <option value="bloqueado">Etapa 3: Solo bloqueo total</option>
            </select>
          </label>
        </div>
      </form>

      <section className="rounded-xl border border-slate-800/80 bg-[#0F172A]">
        <div className="space-y-4 border-b border-slate-800/80 px-5 py-4">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <h2 className="text-base font-semibold text-slate-100">
                Registro persistente de auditoría e incidentes
              </h2>
              <p className="mt-0.5 text-xs text-slate-400">
                Historial almacenado en data/auditoria.json para cumplimiento e
                investigación forense
              </p>
            </div>

            <div className="flex items-center gap-2">
              <a
                href="/api/audit/export?formato=csv"
                download="sentinel_ssh_auditoria.csv"
                className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800 whitespace-nowrap"
              >
                <Download className="h-3.5 w-3.5" />
                <span>Exportar CSV</span>
              </a>
              <a
                href="/api/audit/export?formato=json"
                download="sentinel_ssh_auditoria.json"
                className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800 whitespace-nowrap"
              >
                <Download className="h-3.5 w-3.5" />
                <span>Exportar JSON</span>
              </a>
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-1 rounded-lg bg-[#0B1120] p-1">
              {AUDIT_FILTERS.map((f) => (
                <button
                  key={f.id}
                  type="button"
                  onClick={() => setFilterType(f.id)}
                  className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors whitespace-nowrap ${
                    filterType === f.id
                      ? 'bg-slate-800 text-slate-100'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {f.label}
                </button>
              ))}
            </div>

            <div className="relative w-full sm:w-64">
              <Search className="pointer-events-none absolute top-2.5 left-3 h-3.5 w-3.5 text-slate-500" />
              <input
                type="search"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Buscar IP, usuario o detalle..."
                className="w-full rounded-lg border border-slate-700 bg-[#0B1120] py-1.5 pr-3 pl-8 text-xs text-slate-100 placeholder:text-slate-500 focus:border-sky-400 focus:outline-none"
              />
            </div>
          </div>
        </div>

        {filteredAudit.length === 0 ? (
          <p className="px-5 py-10 text-center text-xs text-slate-400">
            No hay registros de auditoría que coincidan con el filtro actual.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-slate-800/80 text-slate-400">
                <tr>
                  <th className="px-5 py-3 font-medium">Fecha UTC</th>
                  <th className="px-4 py-3 font-medium">Tipo</th>
                  <th className="px-4 py-3 font-medium">IP</th>
                  <th className="px-4 py-3 font-medium">Acción</th>
                  <th className="px-4 py-3 text-right font-medium">Intentos</th>
                  <th className="px-5 py-3 font-medium">Detalle técnico</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredAudit.map((row) => (
                  <tr key={row.id} className="hover:bg-slate-800/30">
                    <td className="px-5 py-2.5 font-mono text-slate-400 tabular-nums whitespace-nowrap">
                      {row.fecha}
                    </td>
                    <td className="px-4 py-2.5 whitespace-nowrap">
                      <StatusLabel estado={row.tipo} />
                    </td>
                    <td className="px-4 py-2.5 font-mono text-slate-100 tabular-nums whitespace-nowrap">
                      {row.ip}
                    </td>
                    <td className="px-4 py-2.5 font-medium text-slate-200">
                      {row.accion}
                    </td>
                    <td className="px-4 py-2.5 text-right font-mono text-slate-300 tabular-nums">
                      {row.intentos}
                    </td>
                    <td className="px-5 py-2.5 text-slate-400">
                      <span
                        className="block max-w-[340px] truncate"
                        title={row.detalle}
                      >
                        {row.detalle}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
