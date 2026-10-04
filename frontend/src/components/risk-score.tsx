import { cn } from '@/lib/utils';

interface RiskScoreProps {
  score: number;
  size?: 'sm' | 'md' | 'lg';
  showLabel?: boolean;
}

function getRiskColor(score: number) {
  if (score >= 85) return { ring: 'stroke-critical', text: 'text-critical', bar: 'bg-critical', label: 'CRITICAL' };
  if (score >= 65) return { ring: 'stroke-high', text: 'text-high', bar: 'bg-high', label: 'HIGH' };
  if (score >= 40) return { ring: 'stroke-medium', text: 'text-medium', bar: 'bg-medium', label: 'MEDIUM' };
  return { ring: 'stroke-low', text: 'text-low', bar: 'bg-low', label: 'LOW' };
}

export function RiskScore({ score, size = 'md', showLabel = true }: RiskScoreProps) {
  const colors = getRiskColor(score);
  const radius = 28;
  const circumference = 2 * Math.PI * radius;
  const progress = (score / 100) * circumference;

  const sizeConfig = {
    sm: { container: 'size-14', text: 'text-sm', label: 'text-[9px]', strokeWidth: 4 },
    md: { container: 'size-20', text: 'text-lg', label: 'text-[10px]', strokeWidth: 5 },
    lg: { container: 'size-28', text: 'text-2xl', label: 'text-xs', strokeWidth: 6 },
  };
  const s = sizeConfig[size];

  return (
    <div className="relative inline-flex flex-col items-center gap-1.5">
      <div className={cn('relative inline-flex items-center justify-center', s.container)}>
        <svg className="absolute inset-0 size-full -rotate-90" viewBox="0 0 72 72" aria-hidden>
          <circle cx="36" cy="36" r={radius} fill="none" className="stroke-muted" strokeWidth={s.strokeWidth} />
          <circle
            cx="36" cy="36" r={radius}
            fill="none"
            className={colors.ring}
            strokeWidth={s.strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={circumference - progress}
            strokeLinecap="round"
          />
        </svg>
        <div className="flex flex-col items-center">
          <span className={cn('font-bold leading-none tabular-nums', s.text, colors.text)}>{score}</span>
          {showLabel && <span className={cn('text-muted-foreground', s.label)}>/100</span>}
        </div>
      </div>
      {showLabel && (
        <span
          className={cn(
            'font-bold tracking-widest',
            s.label === 'text-xs' ? 'text-xs' : 'text-[10px]',
            colors.text
          )}
        >
          {colors.label}
        </span>
      )}
    </div>
  );
}

export function RiskBar({ score, className }: { score: number; className?: string }) {
  const colors = getRiskColor(score);
  return (
    <div className={cn('flex items-center gap-2', className)}>
      <div className="h-1.5 w-16 rounded-full bg-muted overflow-hidden">
        <div className={cn('h-full rounded-full transition-[width]', colors.bar)} style={{ width: `${score}%` }} />
      </div>
      <span className={cn('text-xs font-semibold tabular-nums w-5 text-right', colors.text)}>{score}</span>
    </div>
  );
}
