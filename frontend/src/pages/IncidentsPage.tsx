import { useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, Filter, ArrowUpDown, AlertTriangle, ShieldAlert } from 'lucide-react';
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
import { SeverityBadge, StatusBadge } from '@/components/badges';
import { RiskBar } from '@/components/risk-score';
import { DataError, DataLoading } from '@/components/states';
import { getIncidents } from '@/services/api';
import { useApiData } from '@/hooks/use-api-data';
import type { Severity, IncidentStatus } from '@/types';
import { cn } from '@/lib/utils';

const severities: (Severity | 'all')[] = ['all', 'critical', 'high', 'medium', 'low'];
const statuses: (IncidentStatus | 'all')[] = ['all', 'detected', 'investigating', 'contained', 'resolved', 'false_positive'];

export default function IncidentsPage() {
  const navigate = useNavigate();
  const { data, loading, error, retry } = useApiData(getIncidents, [], { pollMs: 5000 });
  const incidents = data ?? [];
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState<Severity | 'all'>('all');
  const [status, setStatus] = useState<IncidentStatus | 'all'>('all');
  const [sortBy, setSortBy] = useState<'detected' | 'risk'>('detected');

  const filtered = useMemo(() => {
    let list = incidents.filter((i) => {
      const matchesQuery =
        !query ||
        i.id.toLowerCase().includes(query.toLowerCase()) ||
        i.hostname.toLowerCase().includes(query.toLowerCase()) ||
        i.user.toLowerCase().includes(query.toLowerCase()) ||
        i.threatType.toLowerCase().includes(query.toLowerCase());
      const matchesSev = severity === 'all' || i.severity === severity;
      const matchesStatus = status === 'all' || i.status === status;
      return matchesQuery && matchesSev && matchesStatus;
    });
    list = [...list].sort((a, b) => {
      if (sortBy === 'risk') return b.riskScore - a.riskScore;
      return new Date(b.detectedAt).getTime() - new Date(a.detectedAt).getTime();
    });
    return list;
  }, [incidents, query, severity, status, sortBy]);

  return (
    <div className="p-6 space-y-5 max-w-[1600px] mx-auto">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h2 className="text-xl font-bold text-foreground tracking-tight flex items-center gap-2">
            <ShieldAlert className="size-5 text-critical" />
            Security Incidents
          </h2>
          <p className="text-sm text-muted-foreground mt-1">
            Incident response queue — triage, investigate, and respond
          </p>
        </div>
        <p className="text-xs text-muted-foreground tabular-nums bg-muted/50 border border-border rounded-md px-2.5 py-1.5">
          {filtered.length} of {incidents.length} incidents shown
        </p>
      </div>

      {/* Filter toolbar */}
      <div className="flex flex-wrap items-center gap-2 p-2 rounded-lg border border-border bg-card">
        <div className="relative flex-1 min-w-[220px]">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 size-3.5 text-muted-foreground" />
          <Input
            placeholder="Search by ID, hostname, user, or threat…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="pl-8 h-9 text-sm bg-transparent border-0 shadow-none focus-visible:ring-0"
          />
        </div>
        <Select value={severity} onValueChange={(v) => setSeverity(v as Severity | 'all')}>
          <SelectTrigger size="sm" className="w-[135px] bg-muted/40">
            <Filter className="size-3.5 mr-1 text-muted-foreground" />
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent>
            {severities.map((s) => (
              <SelectItem key={s} value={s}>
                {s === 'all' ? 'All Severities' : s.charAt(0).toUpperCase() + s.slice(1)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={status} onValueChange={(v) => setStatus(v as IncidentStatus | 'all')}>
          <SelectTrigger size="sm" className="w-[140px] bg-muted/40">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            {statuses.map((s) => (
              <SelectItem key={s} value={s}>
                {s === 'all' ? 'All Statuses' : s.replace('_', ' ').replace(/\b\w/g, (c) => c.toUpperCase())}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={sortBy} onValueChange={(v) => setSortBy(v as 'detected' | 'risk')}>
          <SelectTrigger size="sm" className="w-[140px] bg-muted/40">
            <ArrowUpDown className="size-3.5 mr-1 text-muted-foreground" />
            <SelectValue placeholder="Sort" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="detected">Newest First</SelectItem>
            <SelectItem value="risk">Highest Risk</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Incident table */}
      <Card className="bg-card border-border overflow-hidden">
        <CardContent className="p-0">
          {loading ? (
            <div className="p-6"><DataLoading rows={6} /></div>
          ) : error ? (
            <DataError message={error} onRetry={retry} />
          ) : filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-center">
              <AlertTriangle className="size-8 text-muted-foreground/50 mb-3" />
              <p className="text-sm text-muted-foreground">No incidents match your filters</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border bg-muted/30">
                    {['Incident ID', 'Threat Type', 'Hostname', 'IP Address', 'User', 'Risk', 'Severity', 'Status', 'Detected', ''].map((h) => (
                      <th key={h} className="px-4 py-2.5 text-left text-[11px] font-semibold text-muted-foreground uppercase tracking-wider whitespace-nowrap first:pl-5 last:pr-5">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((incident) => (
                    <tr
                      key={incident.id}
                      className={cn(
                        'border-b border-border/40 last:border-0 hover:bg-accent/40 cursor-pointer transition-colors',
                        incident.severity === 'critical' && incident.status !== 'resolved' && 'bg-critical/[0.04]'
                      )}
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
                        <span className="text-xs font-mono text-muted-foreground">{incident.ipAddress}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-xs text-muted-foreground">{incident.user}</span>
                      </td>
                      <td className="px-4 py-3">
                        <RiskBar score={incident.riskScore} />
                      </td>
                      <td className="px-4 py-3">
                        <SeverityBadge severity={incident.severity} />
                      </td>
                      <td className="px-4 py-3">
                        <StatusBadge status={incident.status} />
                      </td>
                      <td className="px-4 py-3 text-xs text-muted-foreground whitespace-nowrap tabular-nums">
                        {new Date(incident.detectedAt).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}{' '}
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
          )}
        </CardContent>
      </Card>
    </div>
  );
}
