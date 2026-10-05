import { useState, useMemo } from 'react';
import { Search, Bot, User, Cpu, CheckCircle2, XCircle, Clock, ScrollText } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { DataError, DataLoading } from '@/components/states';
import { getActivityLog } from '@/services/api';
import { useApiData } from '@/hooks/use-api-data';
import { cn } from '@/lib/utils';

const actorIcons = {
  automation: { Icon: Bot, color: 'text-primary', bg: 'bg-primary/15 border-primary/30' },
  analyst: { Icon: User, color: 'text-info', bg: 'bg-info/15 border-info/30' },
  agent: { Icon: Cpu, color: 'text-success', bg: 'bg-success/15 border-success/30' },
};

const resultConfig = {
  success: { Icon: CheckCircle2, color: 'text-success', label: 'Success' },
  failed: { Icon: XCircle, color: 'text-critical', label: 'Failed' },
  pending: { Icon: Clock, color: 'text-warning', label: 'Pending' },
};

export default function ActivityLogPage() {
  const { data, loading, error, retry } = useApiData(getActivityLog, [], { pollMs: 5000 });
  const activityLog = data ?? [];
  const [query, setQuery] = useState('');
  const [actorFilter, setActorFilter] = useState<string>('all');

  const filtered = useMemo(() => {
    return [...activityLog]
      .filter((entry) => {
        const matchesQuery =
          !query ||
          entry.event.toLowerCase().includes(query.toLowerCase()) ||
          entry.target.toLowerCase().includes(query.toLowerCase()) ||
          entry.actor.toLowerCase().includes(query.toLowerCase());
        const matchesActor = actorFilter === 'all' || entry.actorType === actorFilter;
        return matchesQuery && matchesActor;
      })
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  }, [activityLog, query, actorFilter]);

  return (
    <div className="p-6 space-y-5 max-w-[1600px] mx-auto">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h2 className="text-xl font-bold text-foreground tracking-tight flex items-center gap-2">
            <ScrollText className="size-5 text-primary" />
            SOC Activity Log
          </h2>
          <p className="text-sm text-muted-foreground mt-1">Chronological system and analyst actions</p>
        </div>
        <p className="text-xs text-muted-foreground tabular-nums bg-muted/50 border border-border rounded-md px-2.5 py-1.5">
          {filtered.length} of {activityLog.length} entries shown
        </p>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-2 p-2 rounded-lg border border-border bg-card">
        <div className="relative flex-1 min-w-[220px]">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 size-3.5 text-muted-foreground" />
          <Input
            placeholder="Search by event, actor, or target…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="pl-8 h-9 text-sm bg-transparent border-0 shadow-none focus-visible:ring-0"
          />
        </div>
        <Select value={actorFilter} onValueChange={setActorFilter}>
          <SelectTrigger size="sm" className="w-[170px] bg-muted/40">
            <SelectValue placeholder="Actor" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Actors</SelectItem>
            <SelectItem value="automation">Automation Engine</SelectItem>
            <SelectItem value="analyst">SOC Analyst</SelectItem>
            <SelectItem value="agent">Detection Agent</SelectItem>
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
          ) : filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-center">
              <ScrollText className="size-8 text-muted-foreground/50 mb-3" />
              <p className="text-sm text-muted-foreground">No activity matches your filters</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border bg-muted/30">
                    {['Timestamp', 'Event', 'Actor', 'Target', 'Result', 'Details'].map((h) => (
                      <th key={h} className="px-4 py-2.5 text-left text-[11px] font-semibold text-muted-foreground uppercase tracking-wider whitespace-nowrap first:pl-5 last:pr-5">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((entry) => {
                    const actorCfg = actorIcons[entry.actorType];
                    const resultCfg = resultConfig[entry.result];
                    return (
                      <tr key={entry.id} className="border-b border-border/40 last:border-0 hover:bg-accent/40 transition-colors">
                        <td className="px-4 py-3 pl-5 text-xs text-muted-foreground whitespace-nowrap font-mono tabular-nums">
                          {new Date(entry.timestamp).toLocaleString('en-US', {
                            month: 'short',
                            day: 'numeric',
                            hour: '2-digit',
                            minute: '2-digit',
                            second: '2-digit',
                          })}
                        </td>
                        <td className="px-4 py-3">
                          <span className="text-xs font-medium text-foreground">{entry.event}</span>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <div className={cn('flex size-5 items-center justify-center rounded-full border', actorCfg.bg)}>
                              <actorCfg.Icon className={cn('size-3', actorCfg.color)} />
                            </div>
                            <span className="text-xs text-muted-foreground whitespace-nowrap">{entry.actor}</span>
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <span className="text-xs font-mono text-muted-foreground">{entry.target}</span>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-1.5">
                            <resultCfg.Icon className={cn('size-3.5', resultCfg.color)} />
                            <span className={cn('text-xs font-medium', resultCfg.color)}>{resultCfg.label}</span>
                          </div>
                        </td>
                        <td className="px-4 py-3 pr-5">
                          <span className="text-xs text-muted-foreground">{entry.details}</span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
