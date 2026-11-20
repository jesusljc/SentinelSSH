import { Plus, ShieldAlert, Trash2 } from 'lucide-react';
import { type FormEvent, useEffect, useState } from 'react';
import {
  addReputationEntry,
  applyMitigationAction,
  deleteReputationEntry,
  saveConfig,
} from '../api';
import type { DetectorConfig, FirewallEngine, ReputationEntry } from '../types';
import { StatusLabel } from './StatusLabel';

interface ReputationFirewallPanelProps {
  config: DetectorConfig;
  reputacion: ReputationEntry[];
  onRefresh: () => Promise<void>;
  onNotify: (kind: 'ok' | 'error', text: string) => void;
}

export function ReputationFirewallPanel({
  config,
  reputacion,
  onRefresh,
  onNotify,
}: ReputationFirewallPanelProps) {
  const [formConfig, setFormConfig] = useState<DetectorConfig>(config);
  const [savingConfig, setSavingConfig] = useState<boolean>(false);

  const [newTarget, setNewTarget] = useState<string>('');
  const [newType, setNewType] = useState<'lista_blanca' | 'lista_negra'>(
    'lista_blanca',
  );
  const [newLabel, setNewLabel] = useState<string>('');
  const [addingRep, setAddingRep] = useState<boolean>(false);

  const [testIp, setTestIp] = useState<string>('203.0.113.10');

  useEffect(() => {
    setFormConfig(config);
  }, [config]);

  const handleSaveConfig = async (e: FormEvent) => {
    e.preventDefault();
    setSavingConfig(true);
    try {
      await saveConfig(formConfig);
      await onRefresh();
      onNotify('ok', 'Configuración guardada en data/config.json.');
    } catch (err) {
      onNotify(
        'error',
        err instanceof Error ? err.message : 'Error guardando configuración.',
      );
    } finally {
      setSavingConfig(false);
    }
  };

  const handleAddReputation = async (e: FormEvent) => {
    e.preventDefault();
    if (!newTarget.trim()) {
      onNotify('error', 'Ingresa una dirección IP o subred CIDR válida.');
      return;
    }
    setAddingRep(true);
    try {
      await addReputationEntry(newTarget, newType, newLabel);
      setNewTarget('');
      setNewLabel('');
      await onRefresh();
      onNotify('ok', 'Entrada de reputación guardada en data/reputacion.json.');
    } catch (err) {
      onNotify(
        'error',
        err instanceof Error ? err.message : 'No se pudo agregar la IP/CIDR.',
      );
    } finally {
      setAddingRep(false);
    }
  };

  const handleDeleteReputation = async (id: string) => {
    try {
      await deleteReputationEntry(id);
      await onRefresh();
      onNotify('ok', 'Entrada eliminada de la lista de reputación.');
    } catch (err) {
      onNotify(
        'error',
        err instanceof Error ? err.message : 'No se pudo eliminar.',
      );
    }
  };

  const handleTestManualBlock = async () => {
    try {
      const res = await applyMitigationAction(
        testIp,
        'bloquear',
        'Prueba manual de firewall desde panel',
      );
      onNotify('ok', res.mensaje);
      await onRefresh();
    } catch (err) {
      onNotify(
        'error',
        err instanceof Error ? err.message : 'Acción bloqueada por salvaguarda.',
      );
    }
  };

  const previewCommands = (engine: FirewallEngine) => {
    const sampleIp = '198.51.100.77';
    if (engine === 'ufw') {
      return {
        limit: `ufw insert 1 limit from ${sampleIp} to any port 22 proto tcp`,
        drop: `ufw insert 1 deny from ${sampleIp} to any port 22 proto tcp`,
      };
    }
    if (engine === 'nftables') {
      return {
        limit: `nft add rule inet filter input ip saddr ${sampleIp} tcp dport 22 limit rate 3/minute accept`,
        drop: `nft insert rule inet filter input ip saddr ${sampleIp} tcp dport 22 drop`,
      };
    }
    return {
      limit: `iptables -I INPUT 1 -s ${sampleIp} -p tcp --dport 22 -m hashlimit --hashlimit-above 3/min --hashlimit-burst 3 --hashlimit-mode srcip --hashlimit-name ssh_limit -j DROP`,
      drop: `iptables -I INPUT 1 -s ${sampleIp} -p tcp --dport 22 -j DROP`,
    };
  };

  const commands = previewCommands(formConfig.motor_firewall);

  return (
    <div className="space-y-6">
      <form
        onSubmit={handleSaveConfig}
        className="rounded-xl border border-slate-800/80 bg-[#0F172A] p-5"
      >
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
          <div>
            <h2 className="text-base font-semibold text-slate-100">
              Umbrales de detección, firewall y salvaguardas
            </h2>
            <p className="mt-0.5 text-xs text-slate-400">
              Define las 3 etapas de respuesta escalante y protege tu IP de
              administración contra autobloqueos
            </p>
          </div>
          <button
            type="submit"
            disabled={savingConfig}
            className="rounded-lg bg-sky-500 px-4 py-2 text-xs font-semibold text-slate-950 transition-colors hover:bg-sky-400 disabled:opacity-50 whitespace-nowrap"
          >
            {savingConfig ? 'Guardando...' : 'Guardar configuración'}
          </button>
        </div>

        <div className="mt-5 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <label className="block space-y-1.5 text-xs">
            <span className="font-medium text-slate-300">
              Etapa 1: Umbral de alerta
            </span>
            <input
              type="number"
              min={1}
              max={50}
              value={formConfig.umbral_alerta}
              onChange={(e) =>
                setFormConfig({
                  ...formConfig,
                  umbral_alerta: Number(e.target.value),
                })
              }
              className="w-full rounded-lg border border-slate-700 bg-[#0B1120] px-3 py-2 font-mono text-slate-100 focus:border-sky-400 focus:outline-none"
            />
          </label>

          <label className="block space-y-1.5 text-xs">
            <span className="font-medium text-slate-300">
              Etapa 2: Limitación de tasa
            </span>
            <input
              type="number"
              min={2}
              max={100}
              value={formConfig.umbral_limitacion}
              onChange={(e) =>
                setFormConfig({
                  ...formConfig,
                  umbral_limitacion: Number(e.target.value),
                })
              }
              className="w-full rounded-lg border border-slate-700 bg-[#0B1120] px-3 py-2 font-mono text-slate-100 focus:border-sky-400 focus:outline-none"
            />
          </label>

          <label className="block space-y-1.5 text-xs">
            <span className="font-medium text-slate-300">
              Etapa 3: Bloqueo completo
            </span>
            <input
              type="number"
              min={3}
              max={200}
              value={formConfig.umbral_bloqueo}
              onChange={(e) =>
                setFormConfig({
                  ...formConfig,
                  umbral_bloqueo: Number(e.target.value),
                })
              }
              className="w-full rounded-lg border border-slate-700 bg-[#0B1120] px-3 py-2 font-mono text-slate-100 focus:border-sky-400 focus:outline-none"
            />
          </label>

          <label className="block space-y-1.5 text-xs">
            <span className="font-medium text-slate-300">
              Ventana temporal (minutos)
            </span>
            <input
              type="number"
              min={1}
              max={120}
              value={formConfig.ventana_minutos}
              onChange={(e) =>
                setFormConfig({
                  ...formConfig,
                  ventana_minutos: Number(e.target.value),
                })
              }
              className="w-full rounded-lg border border-slate-700 bg-[#0B1120] px-3 py-2 font-mono text-slate-100 focus:border-sky-400 focus:outline-none"
            />
          </label>

          <label className="block space-y-1.5 text-xs">
            <span className="font-medium text-slate-300">
              Auto-desbloqueo (24–48 h)
            </span>
            <input
              type="number"
              min={1}
              max={168}
              value={formConfig.horas_desbloqueo_auto}
              onChange={(e) =>
                setFormConfig({
                  ...formConfig,
                  horas_desbloqueo_auto: Number(e.target.value),
                })
              }
              className="w-full rounded-lg border border-slate-700 bg-[#0B1120] px-3 py-2 font-mono text-slate-100 focus:border-sky-400 focus:outline-none"
            />
          </label>

          <label className="block space-y-1.5 text-xs">
            <span className="font-medium text-slate-300">
              Peso de usuario inválido
            </span>
            <input
              type="number"
              min={1}
              max={5}
              value={formConfig.peso_usuario_invalido}
              onChange={(e) =>
                setFormConfig({
                  ...formConfig,
                  peso_usuario_invalido: Number(e.target.value),
                })
              }
              className="w-full rounded-lg border border-slate-700 bg-[#0B1120] px-3 py-2 font-mono text-slate-100 focus:border-sky-400 focus:outline-none"
            />
          </label>

          <label className="block space-y-1.5 text-xs">
            <span className="font-medium text-slate-300">
              Motor de firewall Linux
            </span>
            <select
              value={formConfig.motor_firewall}
              onChange={(e) =>
                setFormConfig({
                  ...formConfig,
                  motor_firewall: e.target.value as FirewallEngine,
                })
              }
              className="w-full rounded-lg border border-slate-700 bg-[#0B1120] px-3 py-2 text-slate-100 focus:border-sky-400 focus:outline-none"
            >
              <option value="iptables">iptables (hashlimit + DROP)</option>
              <option value="ufw">UFW (limit + deny)</option>
              <option value="nftables">nftables (inet filter)</option>
            </select>
          </label>

          <label className="block space-y-1.5 text-xs">
            <span className="font-medium text-slate-300">
              IP protegida del administrador
            </span>
            <input
              type="text"
              value={formConfig.ip_administrador}
              onChange={(e) =>
                setFormConfig({
                  ...formConfig,
                  ip_administrador: e.target.value,
                })
              }
              placeholder="203.0.113.10"
              className="w-full rounded-lg border border-slate-700 bg-[#0B1120] px-3 py-2 font-mono text-slate-100 focus:border-sky-400 focus:outline-none"
            />
          </label>
        </div>

        <div className="mt-4 flex flex-wrap items-center justify-between gap-4 border-t border-slate-800/60 pt-4">
          <label className="inline-flex cursor-pointer items-center gap-2 text-xs text-slate-300">
            <input
              type="checkbox"
              checked={formConfig.proteger_redes_privadas}
              onChange={(e) =>
                setFormConfig({
                  ...formConfig,
                  proteger_redes_privadas: e.target.checked,
                })
              }
              className="h-4 w-4 rounded border-slate-700 bg-[#0B1120] accent-sky-500"
            />
            <span>
              Excluir redes privadas RFC1918 (10.0.0.0/8, 172.16.0.0/12,
              192.168.0.0/16) de bloqueos automáticos
            </span>
          </label>

          <div className="flex items-center gap-2">
            <input
              type="text"
              value={testIp}
              onChange={(e) => setTestIp(e.target.value)}
              aria-label="IP para probar bloqueo manual o salvaguarda"
              className="w-36 rounded-lg border border-slate-700 bg-[#0B1120] px-2.5 py-1.5 font-mono text-xs text-slate-200 focus:border-sky-400 focus:outline-none"
            />
            <button
              type="button"
              onClick={handleTestManualBlock}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800 whitespace-nowrap"
            >
              <ShieldAlert className="h-3.5 w-3.5 text-amber-400" />
              <span>Probar bloqueo / salvaguarda</span>
            </button>
          </div>
        </div>

        <div className="mt-4 rounded-lg border border-slate-800 bg-[#0B1120] p-3.5 font-mono text-xs text-slate-300">
          <div className="text-slate-500">
            Vista previa de comandos ({formConfig.motor_firewall}):
          </div>
          <div className="mt-1.5 text-amber-300">{commands.limit}</div>
          <div className="mt-1 text-red-400">{commands.drop}</div>
        </div>
      </form>

      <section className="rounded-xl border border-slate-800/80 bg-[#0F172A]">
        <div className="border-b border-slate-800/80 px-5 py-4">
          <h2 className="text-base font-semibold text-slate-100">
            Base de reputación IP (Lista blanca y Lista negra)
          </h2>
          <p className="mt-0.5 text-xs text-slate-400">
            Evita falsos positivos excluyendo oficinas y socios de confianza, o
            marca IPs conocidas como maliciosas
          </p>

          <form
            onSubmit={handleAddReputation}
            className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-12"
          >
            <input
              type="text"
              value={newTarget}
              onChange={(e) => setNewTarget(e.target.value)}
              placeholder="IP o CIDR (ej. 198.51.100.0/24)"
              className="sm:col-span-4 rounded-lg border border-slate-700 bg-[#0B1120] px-3 py-2 font-mono text-xs text-slate-100 focus:border-sky-400 focus:outline-none"
            />
            <select
              value={newType}
              onChange={(e) =>
                setNewType(e.target.value as 'lista_blanca' | 'lista_negra')
              }
              aria-label="Tipo de lista"
              className="sm:col-span-3 rounded-lg border border-slate-700 bg-[#0B1120] px-3 py-2 text-xs text-slate-100 focus:border-sky-400 focus:outline-none"
            >
              <option value="lista_blanca">Lista blanca (Exenta)</option>
              <option value="lista_negra">Lista negra (Riesgo alto)</option>
            </select>
            <input
              type="text"
              value={newLabel}
              onChange={(e) => setNewLabel(e.target.value)}
              placeholder="Descripción (ej. Oficina Madrid)"
              className="sm:col-span-3 rounded-lg border border-slate-700 bg-[#0B1120] px-3 py-2 text-xs text-slate-100 focus:border-sky-400 focus:outline-none"
            />
            <button
              type="submit"
              disabled={addingRep}
              className="sm:col-span-2 inline-flex items-center justify-center gap-1.5 rounded-lg bg-sky-500 px-3 py-2 text-xs font-semibold text-slate-950 hover:bg-sky-400 disabled:opacity-50 whitespace-nowrap"
            >
              <Plus className="h-3.5 w-3.5" />
              <span>Agregar</span>
            </button>
          </form>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-800/80 text-slate-400">
              <tr>
                <th className="px-5 py-3 font-medium">IP / Subred CIDR</th>
                <th className="px-4 py-3 font-medium">Clasificación</th>
                <th className="px-4 py-3 font-medium">Descripción</th>
                <th className="px-4 py-3 font-medium">Origen</th>
                <th className="px-5 py-3 text-right font-medium">Acción</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {reputacion.map((entry) => (
                <tr key={entry.id} className="hover:bg-slate-800/30">
                  <td className="px-5 py-3 font-mono text-slate-100 tabular-nums whitespace-nowrap">
                    {entry.objetivo}
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <StatusLabel estado={entry.tipo} />
                  </td>
                  <td className="px-4 py-3 text-slate-300">{entry.etiqueta}</td>
                  <td className="px-4 py-3 text-slate-400 whitespace-nowrap">
                    {entry.origen}
                  </td>
                  <td className="px-5 py-3 text-right whitespace-nowrap">
                    {entry.origen === 'sistema' ? (
                      <span className="text-slate-500">Protegida del sistema</span>
                    ) : (
                      <button
                        type="button"
                        onClick={() => handleDeleteReputation(entry.id)}
                        className="inline-flex items-center gap-1 text-slate-400 hover:text-red-400"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                        <span>Eliminar</span>
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
