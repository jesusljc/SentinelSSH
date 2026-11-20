import {
  Activity,
  BookOpen,
  FileSearch,
  History,
  Shield,
  X,
} from 'lucide-react';
import type { NavView } from '../types';

interface SidebarProps {
  activeView: NavView;
  onSelectView: (view: NavView) => void;
  mobileOpen: boolean;
  onCloseMobile: () => void;
  activeBlockCount: number;
}

const NAV_ITEMS: Array<{
  id: NavView;
  label: string;
  description: string;
  Icon: typeof Activity;
}> = [
  {
    id: 'monitoreo',
    label: 'Monitoreo',
    description: 'Resumen y mitigaciones',
    Icon: Activity,
  },
  {
    id: 'analizador',
    label: 'Analizador y Simulador',
    description: 'Logs reales y pruebas',
    Icon: FileSearch,
  },
  {
    id: 'reputacion',
    label: 'Reputación y Firewall',
    description: 'CIDR, umbrales y reglas',
    Icon: Shield,
  },
  {
    id: 'auditoria',
    label: 'Auditoría y Slack',
    description: 'Historial y alertas',
    Icon: History,
  },
  {
    id: 'agente',
    label: 'Agente Python y Guías',
    description: 'Descarga y hardening',
    Icon: BookOpen,
  },
];

export function Sidebar({
  activeView,
  onSelectView,
  mobileOpen,
  onCloseMobile,
  activeBlockCount,
}: SidebarProps) {
  return (
    <>
      {mobileOpen && (
        <div
          className="fixed inset-0 z-30 bg-slate-950/70 lg:hidden"
          onClick={onCloseMobile}
          aria-hidden="true"
        />
      )}

      <aside
        className={`fixed inset-y-0 left-0 z-40 flex w-[252px] shrink-0 flex-col border-r border-slate-800/80 bg-[#0F172A] transition-transform duration-200 lg:static lg:translate-x-0 ${
          mobileOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <div className="flex h-16 items-center justify-between border-b border-slate-800/80 px-5">
          <span className="font-display text-lg font-semibold tracking-tight text-slate-100 whitespace-nowrap">
            SentinelSSH
          </span>
          <button
            type="button"
            onClick={onCloseMobile}
            className="rounded-md p-1.5 text-slate-400 hover:bg-slate-800 hover:text-slate-100 lg:hidden"
            aria-label="Cerrar menú"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <nav className="flex-1 space-y-1 px-3 py-4" aria-label="Navegación principal">
          {NAV_ITEMS.map(({ id, label, description, Icon }) => {
            const isActive = activeView === id;
            return (
              <button
                key={id}
                type="button"
                onClick={() => {
                  onSelectView(id);
                  onCloseMobile();
                }}
                className={`flex w-full items-start gap-3 rounded-lg px-3 py-2.5 text-left transition-colors ${
                  isActive
                    ? 'bg-sky-500/12 text-sky-300'
                    : 'text-slate-300 hover:bg-slate-800/60 hover:text-slate-100'
                }`}
              >
                <Icon
                  className={`mt-0.5 h-4 w-4 shrink-0 ${
                    isActive ? 'text-sky-400' : 'text-slate-400'
                  }`}
                  aria-hidden="true"
                />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate text-sm font-medium">{label}</span>
                    {id === 'monitoreo' && activeBlockCount > 0 && (
                      <span className="font-mono text-xs tabular-nums text-red-400">
                        {activeBlockCount}
                      </span>
                    )}
                  </div>
                  <p className="truncate text-xs text-slate-500">{description}</p>
                </div>
              </button>
            );
          })}
        </nav>

        <div className="border-t border-slate-800/80 px-5 py-4 text-xs text-slate-400">
          <div className="font-medium text-slate-300">Motor Python 3.11</div>
          <div className="mt-1 flex items-center gap-1.5 text-slate-500">
            <span>Almacén JSON local</span>
            <span aria-hidden="true">·</span>
            <span>PEP 8</span>
          </div>
        </div>
      </aside>
    </>
  );
}
