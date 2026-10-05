import React from 'react';
import { useNavigate } from 'react-router-dom';
import {
  AlertTriangle,
  Monitor,
  Bell,
  Database,
  ArrowRight,
  Clock,
  Zap,
  CheckCircle2,
  TrendingUp,
  Activity,
  User,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  Cell,
} from 'recharts';
import { SeverityBadge, StatusBadge, NetworkBadge } from '@/components/badges';
import { RiskScore, RiskBar } from '@/components/risk-score';
import { DataError, DashboardSkeleton } from '@/components/states';
import { getDashboard, getIncidents } from '@/services/api';
import { useApiData } from '@/hooks/use-api-data';
import { computeResponseSeconds, cn } from '@/lib/utils';

/* Chart colors read from the theme tokens — adapt to light/dark automatically. */
const severityColors: Record<string, string> = {
  Critical: 'var(--critical)',
  High: 'var(--high)',
  Medium: 'var(--medium)',
  Low: 'var(--low)',
};

const tooltipStyle = {
  background: 'var(--popover)',
  border: '1px solid var(--border)',
  borderRadius: '8px',
  fontSize: 12,
  color: 'var(--popover-foreground)',
  boxShadow: '0 4px 16px rgb(0 0 0 / 0.15)',
} as const;

interface KpiCardProps {
  title: string;
  value: string | number;
  description: string;
  icon: React.ElementType;
  tone: 'critical' | 'success' | 'warning' | 'info';
}

function KpiCard({ title, value, description, icon: Icon, tone }: KpiCardProps) {
  const toneClasses = {
    critical: 'bg-critical/10 text-critical border-critical/20',
    success: 'bg-success/10 text-success border-success/20',
    warning: 'bg-warning/10 text-warning border-warning/20',
    info: 'bg-info/10 text-info border-info/20',
  }[tone];
  const dotClasses = {
    critical: 'bg-critical',
    success: 'bg-success',
    warning: 'bg-warning',
    info: 'bg-info',
  }[tone];

  return (
    <Card className="bg-card border-border transition-all duration-200 hover:border-primary/40 hover:shadow-md hover:shadow-black/[0.04] hover:-translate-y-px">
      <CardContent className="p-5">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <p className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider">{title}</p>
            <p className="text-3xl font-bold mt-2 leading-none tabular-nums tracking-tight">{value}</p>
            <p className="text-xs text-muted-foreground mt-2 flex items-center gap-1.5">
              <span className={cn('size-1.5 rounded-full', dotClasses)} />
              {description}
            </p>
          </div>
          <div className={cn('flex size-10 items-center justify-center rounded-lg border flex-shrink-0', toneClasses)}>
            <Icon className="size-5" />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

export default function DashboardPage() {
  const navigate = useNavigate();
  const { data: dashData, loading: dashLoading, error: dashError, retry: dashRetry } = useApiData(getDashboard, [], { pollMs: 5000 });
  const { data: incidentData, loading: incLoading, error: incError, retry: incRetry } = useApiData(getIncidents, [], { pollMs: 5000 });

  if (dashLoading || incLoading) {
    return (
      <div className="p-6 space-y-6">
        <div>
          <h2 className="text-xl font-bold text-foreground tracking-tight">Security Operations Overview</h2>
          <p className="text-sm text-muted-foreground mt-1">
            Real-time ransomware detection and automated containment monitoring
          </p>
        </div>
        <DashboardSkeleton />
      </div>
    );
  }

  if (dashError || incError || !dashData || !incidentData) {
    return (
      <div className="p-6 space-y-6">
        <div>
          <h2 className="text-xl font-bold text-foreground tracking-tight">Security Operations Overview</h2>
          <p className="text-sm text-muted-foreground mt-1">
            Real-time ransomware detection and automated containment monitoring
          </p>
        </div>
        <DataError
          message={dashError ?? incError ?? 'No dashboard data available'}
          onRetry={() => { dashRetry(); incRetry(); }}
        />
      </div>
    );
  }

  const { stats, incidentsOverTime, severityDistribution } = dashData;
  const incidents = incidentData;
  const primaryIncident = incidents[0];
  const recentIncidents = incidents.slice(0, 5);
  const activeCriticalCount = incidents.filter(
    (i) => i.severity === 'critical' && i.status !== 'resolved' && i.status !== 'false_positive',
  ).length;
  const primaryTimeline = primaryIncident?.timeline ?? [];
  const responseSeconds = computeResponseSeconds(primaryTimeline);
  const detectedAtLabel = primaryIncident
    ? new Date(primaryIncident.detectedAt).toLocaleTimeString('en-US', { hour12: false })
    : '';

  return (
    <div className="p-6 space-y-6 max-w-[1600px] mx-auto">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-foreground tracking-tight">Security Operations Overview</h2>
        <p className="text-sm text-muted-foreground mt-1">
          Real-time ransomware detection and automated containment monitoring
        </p>
      </div>

      {/* KPI cards */}
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
        <KpiCard
          title="Active Incidents"
          value={stats.activeIncidents}
          description={`${activeCriticalCount} critical`}
          icon={AlertTriangle}
          tone="critical"
        />
        <KpiCard
          title="Contained Hosts"
          value={stats.containedHosts}
          description="Network isolated"
          icon={Monitor}
          tone="success"
        />
        <KpiCard
          title="Critical Alerts"
          value={stats.criticalAlerts}
          description="Requires attention"
          icon={Bell}
          tone="warning"
        />
        <KpiCard
          title="Evidence Collected"
          value={stats.evidenceCollected}
          description="Artifacts secured"
          icon={Database}
          tone="info"
        />
      </div>

      {/* Active incident + performance */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        {/* Active incident card */}
        <div className="xl:col-span-2">
          {primaryIncident && (
            <Card className="bg-card border-critical/25 relative overflow-hidden h-full transition-all duration-200 hover:border-critical/40 hover:shadow-lg hover:shadow-critical/[0.06]">
              <div className="absolute top-0 inset-x-0 h-0.5 bg-gradient-to-r from-critical/70 via-critical to-critical/70" />
              <CardHeader className="pb-4">
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 mb-2">
                      <span className="relative flex size-2">
                        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-critical opacity-60" />
                        <span className="relative inline-flex rounded-full size-2 bg-critical" />
                      </span>
                      <span className="text-[11px] font-semibold text-critical uppercase tracking-wider">
                        Active Critical Incident
                      </span>
                    </div>
                    <CardTitle className="text-lg font-bold tracking-tight">{primaryIncident.threatType}</CardTitle>
                    <CardDescription className="mt-1.5 flex items-center gap-1.5 text-xs">
                      <Clock className="size-3" />
                      Detected at {detectedAtLabel}
                      {responseSeconds != null && (
                        <> — automated containment applied in {responseSeconds.toFixed(1)}s</>
                      )}
                    </CardDescription>
                  </div>
                  <RiskScore score={primaryIncident.riskScore} size="md" />
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Incident metadata */}
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-x-4 gap-y-3.5 rounded-lg border border-border/60 bg-muted/30 p-4">
                  {[
                    { label: 'Incident ID', value: primaryIncident.id, mono: true },
                    { label: 'Hostname', value: primaryIncident.hostname, mono: true },
                    { label: 'IP Address', value: primaryIncident.ipAddress, mono: true },
                    { label: 'User', value: primaryIncident.user, icon: User },
                    { label: 'Department', value: primaryIncident.department },
                    { label: 'OS', value: primaryIncident.os },
                  ].map(({ label, value, mono, icon: Icon }) => (
                    <div key={label} className="min-w-0">
                      <p className="text-[10px] text-muted-foreground uppercase tracking-wider font-medium flex items-center gap-1">
                        {Icon && <Icon className="size-3" />}
                        {label}
                      </p>
                      <p className={cn('text-[13px] font-medium text-foreground mt-1 truncate', mono && 'font-mono')}>
                        {value}
                      </p>
                    </div>
                  ))}
                </div>

                {/* Status badges */}
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={primaryIncident.severity} />
                  <StatusBadge status={primaryIncident.status} />
                  <NetworkBadge status={primaryIncident.networkStatus} />
                  <span className="text-xs text-muted-foreground ml-auto">
                    Risk Score: <span className="font-semibold text-critical tabular-nums">{primaryIncident.riskScore}/100</span>
                  </span>
                </div>

                <Button
                  onClick={() => navigate(`/incidents/${primaryIncident.id}`)}
                  className="w-full sm:w-auto bg-critical/10 border border-critical/30 text-critical hover:bg-critical/20 hover:text-critical"
                  variant="outline"
                  size="sm"
                >
                  View Incident Details
                  <ArrowRight className="size-3.5" />
                </Button>
              </CardContent>
            </Card>
          )}
        </div>

        {/* Response performance */}
        <Card className="bg-card border-border h-full">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Zap className="size-4 text-primary" />
              Response Performance
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {[
              { label: 'Avg Detection Time', value: stats.avgDetectionTime, color: 'text-success' },
              { label: 'Avg Containment Time', value: stats.avgContainmentTime, color: 'text-info' },
              { label: 'Automation Success Rate', value: stats.automationSuccessRate, color: 'text-primary' },
            ].map(({ label, value, color }) => (
              <div key={label} className="flex items-center justify-between rounded-md border border-border/60 bg-muted/30 px-3 py-2.5">
                <div className="flex items-center gap-2 min-w-0">
                  <CheckCircle2 className="size-3.5 text-muted-foreground flex-shrink-0" />
                  <span className="text-xs text-muted-foreground truncate">{label}</span>
                </div>
                <span className={cn('text-sm font-bold tabular-nums flex-shrink-0', color)}>{value}</span>
              </div>
            ))}

            <div className="pt-2">
              <p className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-2">
                Severity Distribution
              </p>
              <div className="h-32">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={severityDistribution} barSize={20} margin={{ top: 4, right: 0, left: -24, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                    <XAxis dataKey="name" tick={{ fontSize: 10, fill: 'var(--muted-foreground)' }} axisLine={false} tickLine={false} />
                    <YAxis tick={{ fontSize: 10, fill: 'var(--muted-foreground)' }} axisLine={false} tickLine={false} allowDecimals={false} />
                    <Tooltip contentStyle={tooltipStyle} cursor={{ fill: 'var(--muted)' }} />
                    <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                      {severityDistribution.map((entry) => (
                        <Cell key={entry.name} fill={severityColors[entry.name] ?? 'var(--muted-foreground)'} fillOpacity={0.85} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Incidents over time */}
      <Card className="bg-card border-border">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Activity className="size-4 text-primary" />
              Incidents Over Time (7 Days)
            </CardTitle>
            <span className="text-xs text-muted-foreground">Last 7 days</span>
          </div>
        </CardHeader>
        <CardContent>
          <div className="h-44">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={incidentsOverTime} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="incidentGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--primary)" stopOpacity={0.28} />
                    <stop offset="95%" stopColor="var(--primary)" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                <XAxis dataKey="name" tick={{ fontSize: 11, fill: 'var(--muted-foreground)' }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fontSize: 11, fill: 'var(--muted-foreground)' }} axisLine={false} tickLine={false} allowDecimals={false} />
                <Tooltip contentStyle={tooltipStyle} cursor={{ stroke: 'var(--border)' }} />
                <Area
                  type="monotone"
                  dataKey="value"
                  stroke="var(--primary)"
                  strokeWidth={2}
                  fill="url(#incidentGradient)"
                  name="Incidents"
                  dot={{ r: 2.5, fill: 'var(--primary)', strokeWidth: 0 }}
                  activeDot={{ r: 4 }}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </CardContent>
      </Card>

      {/* Recent incidents */}
      <Card className="bg-card border-border">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <TrendingUp className="size-4 text-primary" />
              Recent Incidents
            </CardTitle>
            <Button variant="ghost" size="sm" className="text-xs h-7 text-primary hover:text-primary" onClick={() => navigate('/incidents')}>
              View All
              <ArrowRight className="size-3" />
            </Button>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-muted/30">
                  {['Incident ID', 'Threat', 'Endpoint', 'User', 'Severity', 'Risk', 'Status', 'Detected', ''].map((h) => (
                    <th key={h} className="px-4 py-2.5 text-left text-[11px] font-semibold text-muted-foreground uppercase tracking-wider whitespace-nowrap first:pl-5 last:pr-5">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {recentIncidents.map((incident) => (
                  <tr
                    key={incident.id}
                    className="border-b border-border/40 last:border-0 hover:bg-accent/40 cursor-pointer transition-colors"
                    onClick={() => navigate(`/incidents/${incident.id}`)}
                  >
                    <td className="px-4 py-3 pl-5">
                      <span className="font-mono text-xs text-primary font-semibold">{incident.id}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-xs text-foreground">{incident.threatType}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-xs font-mono text-foreground">{incident.hostname}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-xs text-muted-foreground">{incident.user}</span>
                    </td>
                    <td className="px-4 py-3">
                      <SeverityBadge severity={incident.severity} />
                    </td>
                    <td className="px-4 py-3">
                      <RiskBar score={incident.riskScore} />
                    </td>
                    <td className="px-4 py-3">
                      <StatusBadge status={incident.status} />
                    </td>
                    <td className="px-4 py-3 text-xs text-muted-foreground whitespace-nowrap tabular-nums">
                      {new Date(incident.detectedAt).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })}
                    </td>
                    <td className="px-4 py-3 pr-5">
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-7 text-xs text-primary hover:text-primary"
                        onClick={(e) => { e.stopPropagation(); navigate(`/incidents/${incident.id}`); }}
                      >
                        View
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
