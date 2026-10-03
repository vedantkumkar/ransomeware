import { cn } from '@/lib/utils';
import type { Severity, IncidentStatus, NetworkStatus, AgentStatus, EvidenceIntegrity } from '@/types';

/**
 * All colors come from theme tokens (index.css) so every badge adapts
 * automatically to light and dark mode. Severity is never communicated by
 * color alone — each badge also carries a text label.
 */

const severityConfig: Record<Severity, { label: string; classes: string; dot: string }> = {
  critical: { label: 'Critical', classes: 'bg-critical/10 text-critical border-critical/30', dot: 'bg-critical' },
  high: { label: 'High', classes: 'bg-high/10 text-high border-high/30', dot: 'bg-high' },
  medium: { label: 'Medium', classes: 'bg-medium/10 text-medium border-medium/30', dot: 'bg-medium' },
  low: { label: 'Low', classes: 'bg-low/10 text-low border-low/30', dot: 'bg-low' },
};

const statusConfig: Record<IncidentStatus, { label: string; classes: string; dot: string }> = {
  detected: { label: 'Detected', classes: 'bg-info/10 text-info border-info/30', dot: 'bg-info' },
  investigating: { label: 'Investigating', classes: 'bg-warning/10 text-warning border-warning/30', dot: 'bg-warning' },
  contained: { label: 'Contained', classes: 'bg-success/10 text-success border-success/30', dot: 'bg-success' },
  resolved: { label: 'Resolved', classes: 'bg-muted/60 text-muted-foreground border-border', dot: 'bg-muted-foreground' },
  false_positive: { label: 'False Positive', classes: 'bg-muted/60 text-muted-foreground border-border', dot: 'bg-muted-foreground' },
};

function Badge({
  label,
  classes,
  dot,
  className,
  uppercase = false,
}: {
  label: string;
  classes: string;
  dot?: string;
  className?: string;
  uppercase?: boolean;
}) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[11px] font-semibold whitespace-nowrap',
        uppercase && 'uppercase tracking-wide',
        classes,
        className
      )}
    >
      {dot && <span className={cn('size-1.5 rounded-full', dot)} />}
      {label}
    </span>
  );
}

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  const c = severityConfig[severity];
  return <Badge label={c.label} classes={c.classes} dot={c.dot} className={className} uppercase />;
}

export function StatusBadge({ status, className }: { status: IncidentStatus; className?: string }) {
  const c = statusConfig[status];
  return <Badge label={c.label} classes={c.classes} dot={c.dot} className={className} />;
}

export function NetworkBadge({ status }: { status: NetworkStatus }) {
  if (status === 'isolated') {
    return <Badge label="Isolated" classes="bg-critical/10 text-critical border-critical/30" dot="bg-critical" />;
  }
  return <Badge label="Connected" classes="bg-success/10 text-success border-success/30" dot="bg-success" />;
}

export function AgentBadge({ status }: { status: AgentStatus }) {
  const configs = {
    online: { label: 'Online', classes: 'bg-success/10 text-success border-success/30', dot: 'bg-success' },
    offline: { label: 'Offline', classes: 'bg-muted/60 text-muted-foreground border-border', dot: 'bg-muted-foreground' },
    degraded: { label: 'Degraded', classes: 'bg-warning/10 text-warning border-warning/30', dot: 'bg-warning' },
  };
  const c = configs[status];
  return <Badge label={c.label} classes={c.classes} dot={c.dot} />;
}

export function IntegrityBadge({ integrity, withTooltip = false }: { integrity: EvidenceIntegrity; withTooltip?: boolean }) {
  const configs: Record<EvidenceIntegrity, { label: string; classes: string; dot?: string; title: string }> = {
    verified: {
      label: 'Integrity Verified',
      classes: 'bg-success/10 text-success border-success/30',
      dot: 'bg-success',
      title: 'Integrity verified — the stored artifact matches its recorded SHA-256 hash.',
    },
    verification_failed: {
      label: 'Verification Failed',
      classes: 'bg-critical/10 text-critical border-critical/30',
      dot: 'bg-critical',
      title: 'The stored artifact no longer matches its recorded SHA-256 hash.',
    },
    artifact_missing: {
      label: 'Artifact Missing',
      classes: 'bg-critical/10 text-critical border-critical/30',
      title: 'The stored artifact file is missing — integrity cannot be verified.',
    },
    not_verified: {
      label: 'Not Verified',
      classes: 'bg-warning/10 text-warning border-warning/30',
      title: 'The artifact has not been checked against its recorded SHA-256 hash.',
    },
    pending: {
      label: 'Pending',
      classes: 'bg-warning/10 text-warning border-warning/30',
      title: 'Integrity verification has not been performed yet.',
    },
    failed: {
      label: 'Failed',
      classes: 'bg-critical/10 text-critical border-critical/30',
      title: 'The stored artifact no longer matches its recorded SHA-256 hash.',
    },
  };
  const c = configs[integrity] ?? configs.not_verified;
  const badge = <Badge label={c.label} classes={c.classes} dot={c.dot} />;
  if (!withTooltip) return badge;
  return (
    <span title={c.title} className="cursor-help">
      {badge}
    </span>
  );
}
