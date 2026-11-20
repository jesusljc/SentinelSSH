import { Copy, Download, Play } from 'lucide-react';
import { useEffect, useState } from 'react';
import { fetchAgentPackage, fetchLogSamples } from '../api';
import type { AgentPackage, LogSample } from '../types';

interface AgentDocsPanelProps {
  onLoadSampleInAnalyzer: (logs: string, sistema: string) => void;
  onNotify: (kind: 'ok' | 'error', text: string) => void;
}

type CodeTab = 'script_python' | 'config_json' | 'systemd_service';
type DocTab =
  | 'buenas_practicas'
  | 'rotacion_inodos'
  | 'sensibilidad'
  | 'alternativas'
  | 'muestras';

function downloadTextFile(filename: string, content: string): void {
  const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

export function AgentDocsPanel({
  onLoadSampleInAnalyzer,
  onNotify,
}: AgentDocsPanelProps) {
  const [pkg, setPkg] = useState<AgentPackage | null>(null);
  const [samples, setSamples] = useState<LogSample[]>([]);
  const [codeTab, setCodeTab] = useState<CodeTab>('script_python');
  const [docTab, setDocTab] = useState<DocTab>('buenas_practicas');

  useEffect(() => {
    Promise.all([fetchAgentPackage(), fetchLogSamples()])
      .then(([agentRes, samplesRes]) => {
        setPkg(agentRes);
        setSamples(samplesRes.muestras);
      })
      .catch((err) => {
        onNotify(
          'error',
          err instanceof Error
            ? err.message
            : 'No se pudo cargar el agente Python.',
        );
      });
  }, [onNotify]);

  const activeFilename =
    codeTab === 'script_python'
      ? 'ssh_sentinel_agent.py'
      : codeTab === 'config_json'
        ? 'config.json'
        : 'sentinel-ssh.service';

  const activeContent = pkg ? pkg[codeTab] : '';

  const handleCopy = async () => {
    if (!activeContent) return;
    try {
      await navigator.clipboard.writeText(activeContent);
      onNotify('ok', `${activeFilename} copiado al portapapeles.`);
    } catch {
      onNotify('error', 'No se pudo copiar al portapapeles.');
    }
  };

  return (
    <div className="space-y-6">
      <section className="rounded-xl border border-slate-800/80 bg-[#0F172A]">
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800/80 px-5 py-4">
          <div>
            <h2 className="text-base font-semibold text-slate-100">
              Agente Python descargable (PEP 8 · Rotación por inodo · JSON)
            </h2>
            <p className="mt-0.5 text-xs text-slate-400">
              Sincronizado automáticamente con tus umbrales, lista blanca CIDR,
              motor de firewall y Webhook de Slack
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              disabled={!activeContent}
              onClick={handleCopy}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800 disabled:opacity-50 whitespace-nowrap"
            >
              <Copy className="h-3.5 w-3.5" />
              <span>Copiar</span>
            </button>
            <button
              type="button"
              disabled={!activeContent}
              onClick={() => downloadTextFile(activeFilename, activeContent)}
              className="inline-flex items-center gap-1.5 rounded-lg bg-sky-500 px-3.5 py-1.5 text-xs font-semibold text-slate-950 hover:bg-sky-400 disabled:opacity-50 whitespace-nowrap"
            >
              <Download className="h-3.5 w-3.5" />
              <span>Descargar {activeFilename}</span>
            </button>
          </div>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800/80 bg-[#0B1120] px-5 py-2.5">
          <div className="flex items-center gap-1">
            {[
              { id: 'script_python', label: 'ssh_sentinel_agent.py' },
              { id: 'config_json', label: 'config.json' },
              { id: 'systemd_service', label: 'sentinel-ssh.service' },
            ].map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setCodeTab(tab.id as CodeTab)}
                className={`rounded-md px-3 py-1.5 font-mono text-xs transition-colors whitespace-nowrap ${
                  codeTab === tab.id
                    ? 'bg-slate-800 text-sky-300'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          <span className="font-mono text-xs text-slate-500">
            Despliegue: /opt/sentinel-ssh/
          </span>
        </div>

        <pre className="max-h-[380px] overflow-auto bg-[#0B1120] p-5 font-mono text-xs leading-relaxed text-slate-200">
          <code>{activeContent || 'Generando paquete Python...'}</code>
        </pre>
      </section>

      <section className="rounded-xl border border-slate-800/80 bg-[#0F172A]">
        <div className="border-b border-slate-800/80 px-5 py-4">
          <h2 className="text-base font-semibold text-slate-100">
            Documentación técnica de seguridad SSH y despliegue
          </h2>
          <div className="mt-3 flex flex-wrap items-center gap-1 rounded-lg bg-[#0B1120] p-1">
            {[
              { id: 'buenas_practicas', label: 'Buenas prácticas SSH' },
              { id: 'rotacion_inodos', label: 'Rotación de logs e inodos' },
              { id: 'sensibilidad', label: 'Tuning y falsos positivos' },
              { id: 'alternativas', label: 'Fail2ban, VPN y claves' },
              { id: 'muestras', label: 'Muestras reales anotadas' },
            ].map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setDocTab(tab.id as DocTab)}
                className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap ${
                  docTab === tab.id
                    ? 'bg-slate-800 text-slate-100'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        <div className="p-5 text-sm leading-relaxed text-slate-300">
          {docTab === 'buenas_practicas' && (
            <div className="space-y-4">
              <p>
                La detección activa en firewall debe complementar —nunca
                reemplazar— el endurecimiento base de{' '}
                <code className="font-mono text-sky-300">/etc/ssh/sshd_config</code>:
              </p>
              <ul className="list-disc space-y-2 pl-5 text-xs text-slate-300">
                <li>
                  <strong>Autenticación por clave Ed25519</strong>: deshabilita
                  contraseñas con{' '}
                  <code className="font-mono text-slate-100">
                    PasswordAuthentication no
                  </code>{' '}
                  y exige claves asimétricas firmadas.
                </li>
                <li>
                  <strong>Bloqueo de acceso root directo</strong>: configura{' '}
                  <code className="font-mono text-slate-100">
                    PermitRootLogin no
                  </code>{' '}
                  y restringe cuentas mediante{' '}
                  <code className="font-mono text-slate-100">
                    AllowUsers
                  </code>{' '}
                  o grupos dedicados.
                </li>
                <li>
                  <strong>Límite temprano en OpenSSH</strong>: ajusta{' '}
                  <code className="font-mono text-slate-100">
                    MaxAuthTries 3
                  </code>{' '}
                  y{' '}
                  <code className="font-mono text-slate-100">
                    LoginGraceTime 20
                  </code>{' '}
                  para cortar sesiones inactivas de escáneres.
                </li>
              </ul>
            </div>
          )}

          {docTab === 'rotacion_inodos' && (
            <div className="space-y-4 text-xs">
              <p>
                En servidores Linux, <code className="font-mono text-sky-300">logrotate</code>{' '}
                archiva periódicamente{' '}
                <code className="font-mono text-slate-100">/var/log/auth.log</code>{' '}
                (Debian/Ubuntu) o{' '}
                <code className="font-mono text-slate-100">/var/log/secure</code>{' '}
                (RedHat/CentOS). Si un script solo recuerda el número de línea,
                perderá eventos o bloqueará la lectura tras la rotación.
              </p>
              <div className="rounded-lg border border-slate-800 bg-[#0B1120] p-4 space-y-2">
                <div className="font-semibold text-slate-100">
                  Estrategia implementada en estado_agente.json
                </div>
                <p className="text-slate-400">
                  1. El agente guarda <code className="font-mono">st_ino</code>{' '}
                  (inodo del archivo) y <code className="font-mono">offset</code>{' '}
                  en bytes tras cada lectura.
                </p>
                <p className="text-slate-400">
                  2. Si el inodo cambia, lee el remanente pendiente del archivo
                  rotado (<code className="font-mono">.1</code>) antes de abrir
                  el nuevo archivo desde el byte 0.
                </p>
                <p className="text-slate-400">
                  3. Si el tamaño en bytes es menor al offset previo (modo{' '}
                  <code className="font-mono">copytruncate</code>), reinicia el
                  puntero automáticamente.
                </p>
              </div>
            </div>
          )}

          {docTab === 'sensibilidad' && (
            <div className="space-y-3 text-xs">
              <p>
                Para evitar bloquear empleados remotos que escriben mal su
                contraseña:
              </p>
              <ul className="list-disc space-y-2 pl-5">
                <li>
                  <strong>Correlación de éxito posterior</strong>: si una IP
                  registra 1–2 fallos seguidos de{' '}
                  <code className="font-mono text-emerald-400">
                    Accepted password/publickey
                  </code>
                  , SentinelSSH reinicia su puntaje de riesgo como error humano.
                </li>
                <li>
                  <strong>Peso diferenciado</strong>: los intentos contra{' '}
                  <code className="font-mono text-red-400">Invalid user</code>{' '}
                  multiplican el riesgo por 2× porque indican enumeración con
                  diccionarios automatizados.
                </li>
                <li>
                  <strong>Escalamiento gradual</strong>: comienza en alerta (3),
                  limita tasa con <code className="font-mono">hashlimit</code>{' '}
                  (5) y solo aplica <code className="font-mono">DROP</code>{' '}
                  (10) si el ataque persiste, con expiración automática a las
                  24–48 horas.
                </li>
              </ul>
            </div>
          )}

          {docTab === 'alternativas' && (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-slate-800 text-slate-400">
                  <tr>
                    <th className="py-2 pr-4 font-medium">Mecanismo</th>
                    <th className="py-2 pr-4 font-medium">Función principal</th>
                    <th className="py-2 font-medium">Cuándo combinarlo</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  <tr>
                    <td className="py-2.5 pr-4 font-medium text-slate-100">
                      Claves SSH + FIDO2
                    </td>
                    <td className="py-2.5 pr-4">
                      Elimina la superficie de ataque por diccionario.
                    </td>
                    <td className="py-2.5">Siempre obligatorio en producción.</td>
                  </tr>
                  <tr>
                    <td className="py-2.5 pr-4 font-medium text-slate-100">
                      VPN / WireGuard Bastion
                    </td>
                    <td className="py-2.5 pr-4">
                      Oculta el puerto 22 de Internet pública.
                    </td>
                    <td className="py-2.5">
                      Entornos corporativos con IP fija o acceso remoto.
                    </td>
                  </tr>
                  <tr>
                    <td className="py-2.5 pr-4 font-medium text-slate-100">
                      Fail2ban + SentinelSSH
                    </td>
                    <td className="py-2.5 pr-4">
                      Reacción local inmediata en múltiples servicios.
                    </td>
                    <td className="py-2.5">
                      Usa SentinelSSH cuando necesites auditoría JSON,
                      escalamiento y alertas Slack centralizadas.
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          )}

          {docTab === 'muestras' && (
            <div className="space-y-4">
              {samples.map((m) => (
                <div
                  key={m.id}
                  className="rounded-lg border border-slate-800 bg-[#0B1120] p-4"
                >
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <div className="text-sm font-semibold text-slate-100">
                        {m.titulo}
                      </div>
                      <div className="mt-0.5 font-mono text-xs text-slate-400">
                        {m.ruta_linux}
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={() => onLoadSampleInAnalyzer(m.logs, m.sistema)}
                      className="inline-flex items-center gap-1.5 rounded-lg bg-sky-500/15 px-3 py-1.5 text-xs font-medium text-sky-300 hover:bg-sky-500/25 whitespace-nowrap"
                    >
                      <Play className="h-3.5 w-3.5" />
                      <span>Probar en Analizador</span>
                    </button>
                  </div>
                  <p className="mt-2 text-xs text-slate-400">{m.explicacion}</p>
                  <pre className="mt-3 overflow-x-auto rounded border border-slate-800/80 bg-[#0F172A] p-3 font-mono text-[11px] leading-relaxed text-slate-300">
                    {m.logs}
                  </pre>
                </div>
              ))}
            </div>
          )}
        </div>
      </section>
    </div>
  );
}
