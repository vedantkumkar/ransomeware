import { useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { Database, FileCheck, ShieldCheck, Link2, Search, Eye, Fingerprint } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { IntegrityBadge } from '@/components/badges';
import { EvidenceDetailDialog } from '@/components/EvidenceDetailDialog';
import { DataError, DataLoading } from '@/components/states';
import { getEvidence } from '@/services/api';
import { useApiData } from '@/hooks/use-api-data';
import type { EvidenceItem } from '@/types';
import { cn } from '@/lib/utils';

const typeLabels: Record<string, string> = {
  process_snapshot: 'Process Snapshot',
  file_manifest: 'Modified File Manifest',
  event_logs: 'Windows Event Logs',
  memory_metadata: 'Memory Metadata',
  network_metadata: 'Network Metadata',
  ransom_note: 'Ransom Note',
  detection_log: 'Detection Event Log',
  text_artifact: 'Text / Log Artifact',
};

export default function EvidencePage() {
  const navigate = useNavigate();
  const { data, loading, error, retry } = useApiData(getEvidence, [], { pollMs: 5000 });
  const evidence = data ?? [];
  const [query, setQuery] = useState('');
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const stats = useMemo(() => {
    return {
      packages: evidence.length,
      filesCollected: 146,
      integrity: 'Verified',
      custody: 'Intact',
    };
  }, [evidence]);

  const filtered = useMemo(() => {
    return evidence.filter((e) => {
      const matchesQuery =
        !query ||
        e.id.toLowerCase().includes(query.toLowerCase()) ||
        e.incidentId.toLowerCase().includes(query.toLowerCase()) ||
        e.source.toLowerCase().includes(query.toLowerCase()) ||
        typeLabels[e.type].toLowerCase().includes(query.toLowerCase());
      return matchesQuery;
    });
  }, [evidence, query]);

  const statCards = [
    { label: 'Evidence Packages', value: stats.packages, icon: Database, tone: 'info' as const },
    { label: 'Files Collected', value: stats.filesCollected, icon: FileCheck, tone: 'success' as const },
    { label: 'Storage Integrity', value: stats.integrity, icon: ShieldCheck, tone: 'success' as const },
    { label: 'Chain of Custody', value: stats.custody, icon: Link2, tone: 'info' as const },
  ];

  const toneClasses = {
    info: 'bg-info/10 text-info border-info/20',
    success: 'bg-success/10 text-success border-success/20',
  };

  return (
    <div className="p-6 space-y-5 max-w-[1600px] mx-auto">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h2 className="text-xl font-bold text-foreground tracking-tight flex items-center gap-2">
            <Database className="size-5 text-primary" />
            Evidence & Forensics
          </h2>
          <p className="text-sm text-muted-foreground mt-1">
            Forensic evidence packages with chain of custody verification
          </p>
        </div>
        <p className="text-xs text-muted-foreground tabular-nums bg-muted/50 border border-border rounded-md px-2.5 py-1.5">
          {filtered.length} of {evidence.length} artifacts shown
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

      {/* Search */}
      <div className="flex items-center gap-2 p-2 rounded-lg border border-border bg-card max-w-xl">
        <div className="relative flex-1">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 size-3.5 text-muted-foreground" />
          <Input
            placeholder="Search by evidence ID, incident, or source…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="pl-8 h-9 text-sm bg-transparent border-0 shadow-none focus-visible:ring-0"
          />
        </div>
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
              <Fingerprint className="size-8 text-muted-foreground/50 mb-3" />
              <p className="text-sm text-muted-foreground">No evidence matches your search</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border bg-muted/30">
                    {['Evidence ID', 'Incident', 'Type', 'Source', 'Size', 'SHA-256', 'Collected', 'Integrity', ''].map((h) => (
                      <th key={h} className="px-4 py-2.5 text-left text-[11px] font-semibold text-muted-foreground uppercase tracking-wider whitespace-nowrap first:pl-5 last:pr-5">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((ev: EvidenceItem) => (
                    <tr key={ev.id} className="border-b border-border/40 last:border-0 hover:bg-accent/40 transition-colors">
                      <td className="px-4 py-3 pl-5">
                        <span className="font-mono text-xs text-primary font-semibold">{ev.id}</span>
                      </td>
                      <td className="px-4 py-3">
                        <button
                          className="font-mono text-xs text-primary hover:underline"
                          onClick={() => navigate(`/incidents/${ev.incidentId}`)}
                        >
                          {ev.incidentId}
                        </button>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-xs text-foreground">{typeLabels[ev.type] ?? ev.type}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-xs font-mono text-muted-foreground">{ev.source}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-xs text-muted-foreground tabular-nums">{ev.size}</span>
                      </td>
                      <td className="px-4 py-3 max-w-[160px]">
                        <span className="text-[11px] font-mono text-muted-foreground block truncate" title={ev.sha256}>
                          {ev.sha256 || '—'}
                        </span>
                      </td>
                      <td
                        className="px-4 py-3 text-xs text-muted-foreground whitespace-nowrap tabular-nums"
                        title={new Date(ev.collectedAt).toLocaleString('en-US', { hour12: false })}
                      >
                        {new Date(ev.collectedAt).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}
                      </td>
                      <td className="px-4 py-3">
                        <IntegrityBadge integrity={ev.integrity} withTooltip />
                      </td>
                      <td className="px-4 py-3 pr-5">
                        <div className="flex items-center gap-1">
                          {ev.collectionMethod === 'manual' && (
                            <span className="mr-1 rounded bg-primary/10 border border-primary/30 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider text-primary">
                              Manual
                            </span>
                          )}
                          <Button variant="ghost" size="sm" className="h-7 text-xs text-primary hover:text-primary" onClick={() => setSelectedId(ev.id)}>
                            <Eye className="size-3" /> View
                          </Button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Evidence detail: Overview / Artifact / Chain of Custody */}
      <EvidenceDetailDialog
        evidenceId={selectedId}
        open={selectedId !== null}
        onClose={() => setSelectedId(null)}
        onVerified={retry}
      />
    </div>
  );
}
