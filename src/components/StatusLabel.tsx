import { AlertTriangle, CheckCircle2, Eye, ShieldAlert, ShieldBan } from 'lucide-react';

interface StatusLabelProps {
  estado: string;
}

const STATUS_MAP: Record<
  string,
  { label: string; colorClass: string; Icon: typeof ShieldAlert }
> = {
  bloqueado: {
    label: 'Bloqueada',
    colorClass: 'text-red-400',
    Icon: ShieldBan,
  },
  bloqueo: {
    label: 'Bloqueo',
    colorClass: 'text-red-400',
    Icon: ShieldBan,
  },
  tasa_limitada: {
    label: 'Tasa limitada',
    colorClass: 'text-amber-400',
    Icon: AlertTriangle,
  },
  alerta: {
    label: 'Alerta',
    colorClass: 'text-amber-300',
    Icon: ShieldAlert,
  },
  deteccion: {
    label: 'Detección',
    colorClass: 'text-amber-300',
    Icon: ShieldAlert,
  },
  usuario_invalido: {
    label: 'Usuario inválido',
    colorClass: 'text-red-400',
    Icon: ShieldAlert,
  },
  fallo_auth: {
    label: 'Fallo auth',
    colorClass: 'text-amber-400',
    Icon: AlertTriangle,
  },
  exceso_intentos: {
    label: 'Exceso intentos',
    colorClass: 'text-red-400',
    Icon: ShieldBan,
  },
  desconexion_preauth: {
    label: 'Cierre pre-auth',
    colorClass: 'text-slate-300',
    Icon: Eye,
  },
  exitoso: {
    label: 'Acceso exitoso',
    colorClass: 'text-emerald-400',
    Icon: CheckCircle2,
  },
  lista_blanca: {
    label: 'Lista blanca',
    colorClass: 'text-emerald-400',
    Icon: CheckCircle2,
  },
  lista_negra: {
    label: 'Lista negra',
    colorClass: 'text-red-400',
    Icon: ShieldBan,
  },
  salvaguarda: {
    label: 'Salvaguarda',
    colorClass: 'text-sky-400',
    Icon: CheckCircle2,
  },
  falso_positivo: {
    label: 'Falso positivo',
    colorClass: 'text-emerald-400',
    Icon: CheckCircle2,
  },
  desbloqueo: {
    label: 'Desbloqueo',
    colorClass: 'text-sky-400',
    Icon: CheckCircle2,
  },
  slack: {
    label: 'Slack',
    colorClass: 'text-sky-400',
    Icon: Eye,
  },
  observacion: {
    label: 'Observación',
    colorClass: 'text-slate-400',
    Icon: Eye,
  },
};

export function StatusLabel({ estado }: StatusLabelProps) {
  const entry = STATUS_MAP[estado] || {
    label: estado,
    colorClass: 'text-slate-300',
    Icon: Eye,
  };
  const Icon = entry.Icon;

  return (
    <span
      className={`inline-flex items-center gap-1.5 text-xs font-medium whitespace-nowrap ${entry.colorClass}`}
    >
      <Icon className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
      <span>{entry.label}</span>
    </span>
  );
}
