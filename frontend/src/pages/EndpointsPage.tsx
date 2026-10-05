import { useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, Monitor, WifiOff, Power, Activity, ShieldCheck } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from '@/components/ui/dialog';
import { SeverityBadge, AgentBadge, NetworkBadge } from '@/components/badges';
import { RiskBar } from '@/components/risk-score';
import { DataError, DataLoading } from '@/components/states';
import { getEndpoints } from '@/services/api';
import { useApiData } from '@/hooks/use-api-data';
import type { Endpoint } from '@/types';
import { cn } from '@/lib/utils';

export default function EndpointsPage() {
  const navigate = useNavigate();
  const { data, loading, error, retry } = useApiData(getEndpoints, [], { pollMs: 5000 });
  const endpoints = data ?? [];
  const [query, setQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [selected, setSelected] = useState<Endpoint | null>(null);

  const stats = useMemo(() => {
    const total = endpoints.length;
    const online = endpoints.filter((e) => e.agentStatus === 'online').length;
    const isolated = endpoints.filter((e) => e.networkStatus === 'isolated').length;
    const offline = endpoints.filter((e) => e.agentStatus === 'offline').length;
    return { total, online, isolated, offline };
  }, [endpoints]);

  const filtered = useMemo(() => {
    return endpoints.filter((e) => {
      const matchesQuery =
        !query ||
        e.hostname.toLowerCase().includes(query.toLowerCase()) ||
        e.ipAddress.includes(query) ||
        e.user.toLowerCase().includes(query.toLowerCase());
      const matchesStatus =
        statusFilter === 'all' ||
        (statusFilter === 'isolated' && e.networkStatus === 'isolated') ||
        (statusFilter === 'online' && e.agentStatus === 'online' && e.networkStatus === 'connected') ||
        (statusFilter === 'offline' && e.agentStatus === 'offline');
      return matchesQuery && matchesStatus;
    });
  }, [endpoints, query, statusFilter]);

  const statCards = [
    { label: 'Total Endpoints', value: stats.total, icon: Monitor, tone: 'info' as const },
    { label: 'Online', value: stats.online, icon: Activity, tone: 'success' as const },
    { label: 'Isolated', value: stats.isolated, icon: WifiOff, tone: 'critical' as const },
    { label: 'Offline', value: stats.offline, icon: Power, tone: 'muted' as const },
  ];

  const toneClasses = {
    info: 'bg-info/10 text-info border-info/20',
    success: 'bg-success/10 text-success border-success/20',
    critical: 'bg-critical/10 text-critical border-critical/20',
    muted: 'bg-muted text-muted-foreground border-border',
  };

  return (
    <div className="p-6 space-y-5 max-w-[1600px] mx-auto">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h2 className="text-xl font-bold text-foreground tracking-tight flex items-center gap-2">
            <Monitor className="size-5 text-primary" />
            Endpoints
          </h2>
          <p className="text-sm text-muted-foreground mt-1">Monitor and manage protected endpoints</p>
        </div>
        <p className="text-xs text-muted-foreground tabular-nums bg-muted/50 border border-border rounded-md px-2.5 py-1.5">
          {filtered.length} of {endpoints.length} endpoints shown
        </p>
      </div>

      {/* Summary */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {statCards.map(({ label, value, icon: Icon, tone }) => (
          <Card key={label} className="bg-card border-border transition-all duration-200 hover:border-primary/40 hover:shadow-md hover:shadow-black/[0.04] hover:-translate-y-px">
            <CardContent className="p-4">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <p className="text-[11px] text-muted-foreground uppercase tracking-wider font-medium">{label}</p>
                  <p className="text-2xl font-bold mt-1.5 tabular-nums tracking-tight">{value}</p>
                </div>
                <div className={cn('flex size-9 items-center justify-center rounded-lg border flex-shrink-0', toneClasses[tone])}>
                  <Icon className="size-4" />
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Filter toolbar */}
      <div className="flex flex-wrap items-center gap-2 p-2 rounded-lg border border-border bg-card">
        <div className="relative flex-1 min-w-[220px]">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 size-3.5 text-muted-foreground" />
          <Input
            placeholder="Search by hostname, IP, or user…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="pl-8 h-9 text-sm bg-transparent border-0 shadow-none focus-visible:ring-0"
          />
        </div>
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger size="sm" className="w-[140px] bg-muted/40">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Statuses</SelectItem>
            <SelectItem value="online">Online</SelectItem>
            <SelectItem value="isolated">Isolated</SelectItem>
            <SelectItem value="offline">Offline</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Table */}
      <Card className="bg-card border-border overflow-hidden">
        <CardContent className="p-0">
          {loading ? (
            <div className="p-6"><DataLoading rows={6} /></div>
          ) : error ? (
            <DataError message={error} onRetry={retry} />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border bg-muted/30">
                    {['Hostname', 'IP Address', 'User', 'OS', 'Agent', 'Risk', 'Network', 'Last Seen', ''].map((h) => (
                      <th key={h} className="px-4 py-2.5 text-left text-[11px] font-semibold text-muted-foreground uppercase tracking-wider whitespace-nowrap first:pl-5 last:pr-5">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((ep) => (
                    <tr
                      key={ep.id}
                      className={cn(
                        'border-b border-border/40 last:border-0 hover:bg-accent/40 cursor-pointer transition-colors',
                        ep.networkStatus === 'isolated' && 'bg-critical/[0.04]'
                      )}
                      onClick={() => setSelected(ep)}
                    >
                      <td className="px-4 py-3 pl-5">
                        <span className="text-xs font-mono font-medium text-foreground">{ep.hostname}</span>
                        {ep.incidentId && (
                          <span className="ml-2 text-[10px] text-primary font-mono">{ep.incidentId}</span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-xs font-mono text-muted-foreground">{ep.ipAddress}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-xs text-muted-foreground">{ep.user}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-xs text-muted-foreground">{ep.os}</span>
                      </td>
                      <td className="px-4 py-3">
                        <AgentBadge status={ep.agentStatus} />
                      </td>
                      <td className="px-4 py-3">
                        {ep.severity === 'none' ? (
                          <span className="text-xs text-muted-foreground">—</span>
                        ) : (
                          <RiskBar score={ep.riskScore} />
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <NetworkBadge status={ep.networkStatus} />
                      </td>
                      <td className="px-4 py-3 text-xs text-muted-foreground whitespace-nowrap">{ep.lastSeen}</td>
                      <td className="px-4 py-3 pr-5">
                        <Button variant="ghost" size="sm" className="h-7 text-xs text-primary hover:text-primary" onClick={(e) => { e.stopPropagation(); setSelected(ep); }}>
                          Details
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Endpoint Detail Dialog */}
      <Dialog open={!!selected} onOpenChange={(open) => !open && setSelected(null)}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Monitor className="size-5 text-primary" />
              {selected?.hostname}
            </DialogTitle>
            <DialogDescription>Endpoint details and security status</DialogDescription>
          </DialogHeader>
          {selected && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                {[
                  { label: 'IP Address', value: selected.ipAddress },
                  { label: 'User', value: selected.user },
                  { label: 'Department', value: selected.department },
                  { label: 'Operating System', value: selected.os },
                  { label: 'Last Seen', value: selected.lastSeen },
                  { label: 'Risk Score', value: `${selected.riskScore}/100` },
                ].map(({ label, value }) => (
                  <div key={label}>
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wider font-medium">{label}</p>
                    <p className="text-sm font-medium text-foreground font-mono mt-0.5">{value}</p>
                  </div>
                ))}
              </div>
              <div className="flex items-center gap-3 pt-3 border-t border-border">
                <div className="space-y-1">
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wider font-medium">Agent</p>
                  <AgentBadge status={selected.agentStatus} />
                </div>
                <div className="space-y-1">
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wider font-medium">Network</p>
                  <NetworkBadge status={selected.networkStatus} />
                </div>
                {selected.severity !== 'none' && (
                  <div className="space-y-1">
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wider font-medium">Severity</p>
                    <SeverityBadge severity={selected.severity} />
                  </div>
                )}
              </div>
              {selected.incidentId && (
                <div className="pt-3 border-t border-border">
                  <Button
                    variant="outline"
                    size="sm"
                    className="w-full"
                    onClick={() => {
                      navigate(`/incidents/${selected.incidentId}`);
                      setSelected(null);
                    }}
                  >
                    <ShieldCheck className="size-4" />
                    View Related Incident {selected.incidentId}
                  </Button>
                </div>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
