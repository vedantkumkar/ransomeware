import { useCallback, useEffect, useState } from 'react';
import {
  Copy,
  Check,
  Fingerprint,
  ShieldCheck,
  Loader2,
  CircleAlert,
  History,
} from 'lucide-react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Button } from '@/components/ui/button';
import { IntegrityBadge } from '@/components/badges';
import { getEvidenceDetail, getEvidenceArtifact, verifyEvidenceIntegrity } from '@/services/api';
import type {
  ArtifactContent,
  EvidenceDetail,
  EvidenceItem,
} from '@/types';
import { cn } from '@/lib/utils';

const TYPE_LABELS: Record<string, string> = {
  process_snapshot: 'Process Snapshot',
  file_manifest: 'Modified File Manifest',
  event_logs: 'Windows Event Logs',
  memory_metadata: 'Memory Metadata',
  network_metadata: 'Network Metadata',
  ransom_note: 'Ransom Note',
  detection_log: 'Detection Event Log',
  text_artifact: 'Text / Log Artifact',
};

/** Exact date + time display, e.g. "Sep 6, 2026 • 17:47:53". */
function formatExact(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return (
    date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) +
    ' • ' +
    date.toLocaleTimeString('en-US', { hour12: false })
  );
}

function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      // clipboard unavailable — ignore
    }
  };
  return (
    <Button variant="ghost" size="sm" className="h-6 px-1.5 text-[11px] text-muted-foreground hover:text-foreground" onClick={() => void copy()}>
      {copied ? <Check className="size-3 text-success" /> : <Copy className="size-3" />}
      {copied ? 'Copied' : label}
    </Button>
  );
}

function Field({ label, children, mono = false }: { label: string; children: React.ReactNode; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <p className="text-[10px] text-muted-foreground uppercase tracking-wider font-medium">{label}</p>
      <div className={cn('text-xs text-foreground mt-0.5 break-all', mono && 'font-mono')}>{children}</div>
    </div>
  );
}

/** Type-aware artifact rendering. Collected artifacts are never executed. */
function ArtifactView({ artifact, evidenceType }: { artifact: ArtifactContent; evidenceType: string }) {
  if (artifact.binaryUnsupported) {
    return (
      <p className="text-xs text-muted-foreground flex items-center gap-2 p-3 rounded-md border border-border bg-muted/30">
        <CircleAlert className="size-4 text-warning" />
        Binary artifact — content is not rendered. Use the recorded metadata and SHA-256 for verification.
      </p>
    );
  }

  let parsed: unknown = null;
  const isJson = artifact.mimeType.includes('json');
  if (isJson) {
    try {
      parsed = JSON.parse(artifact.content);
    } catch {
      parsed = null;
    }
  }

  // Structured rendering for file manifests.
  if (evidenceType === 'file_manifest' && parsed && typeof parsed === 'object') {
    const data = parsed as {
      filesModified?: number;
      filesLocked?: number;
      targetDirectory?: string;
      countersReportedBy?: string;
      directoryScan?: {
        reachable?: boolean;
        notCaptured?: { reason?: string };
        entries?: { name: string; path: string; sizeBytes: number; modifiedAt: string; state: string }[];
      };
    };
    const scan = data.directoryScan;
    return (
      <div className="space-y-3">
        <div className="grid grid-cols-3 gap-3 text-xs">
          <Field label="Target Directory" mono>{data.targetDirectory || '—'}</Field>
          <Field label="Files Modified">{data.filesModified ?? '—'}</Field>
          <Field label="Files Locked">{data.filesLocked ?? '—'}</Field>
        </div>
        <p className="text-[11px] text-muted-foreground">{data.countersReportedBy}</p>
        {scan && !scan.reachable && (
          <p className="text-[11px] text-warning flex items-start gap-1.5 p-2 rounded border border-warning/30 bg-warning/[0.06]">
            <CircleAlert className="size-3.5 mt-0.5 flex-shrink-0" />
            <span>File listing not captured — {scan.notCaptured?.reason ?? 'directory unavailable'}</span>
          </p>
        )}
        {scan?.reachable && (
          <div className="rounded-md border border-border overflow-hidden">
            <table className="w-full text-[11px]">
              <thead>
                <tr className="bg-muted/40 border-b border-border">
                  <th className="text-left px-2.5 py-1.5 font-semibold text-muted-foreground uppercase tracking-wider">File</th>
                  <th className="text-left px-2.5 py-1.5 font-semibold text-muted-foreground uppercase tracking-wider">State</th>
                  <th className="text-right px-2.5 py-1.5 font-semibold text-muted-foreground uppercase tracking-wider">Size</th>
                  <th className="text-left px-2.5 py-1.5 font-semibold text-muted-foreground uppercase tracking-wider">Modified (UTC)</th>
                </tr>
              </thead>
              <tbody className="max-h-56 overflow-y-auto">
                {(scan.entries ?? []).map((entry) => (
                  <tr key={entry.path} className="border-b border-border/40 last:border-0">
                    <td className="px-2.5 py-1.5 font-mono text-foreground truncate max-w-[260px]" title={entry.path}>{entry.name}</td>
                    <td className="px-2.5 py-1.5">
                      <span className={cn(
                        'text-[10px] font-semibold rounded px-1.5 py-0.5',
                        entry.state === 'locked_copy' ? 'bg-critical/10 text-critical'
                          : entry.state === 'ransom_note' ? 'bg-warning/10 text-warning'
                          : 'bg-success/10 text-success',
                      )}>
                        {entry.state.replace('_', ' ')}
                      </span>
                    </td>
                    <td className="px-2.5 py-1.5 text-right tabular-nums text-muted-foreground">{entry.sizeBytes} B</td>
                    <td className="px-2.5 py-1.5 font-mono text-muted-foreground">{entry.modifiedAt}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    );
  }

  // Structured rendering for Windows event logs.
  if (evidenceType === 'event_logs' && parsed && typeof parsed === 'object') {
    const data = parsed as {
      capturedFrom?: string;
      note?: string;
      collectedAt?: string;
      events?: { timeCreated?: string; provider?: string; eventId?: number; level?: string; message?: string }[];
    };
    return (
      <div className="space-y-3">
        <div className="grid grid-cols-2 gap-3 text-xs">
          <Field label="Captured From" mono>{data.capturedFrom || '—'}</Field>
          <Field label="Collected At" mono>{data.collectedAt ? formatExact(data.collectedAt) : '—'}</Field>
        </div>
        {data.note && <p className="text-[11px] text-muted-foreground">{data.note}</p>}
        {(data.events?.length ?? 0) === 0 ? (
          <p className="text-[11px] text-muted-foreground">No events were captured in this artifact.</p>
        ) : (
          <div className="rounded-md border border-border overflow-x-auto max-h-72 overflow-y-auto">
            <table className="w-full text-[11px]">
              <thead className="sticky top-0">
                <tr className="bg-muted/40 border-b border-border">
                  <th className="text-left px-2.5 py-1.5 font-semibold text-muted-foreground uppercase tracking-wider">Time</th>
                  <th className="text-left px-2.5 py-1.5 font-semibold text-muted-foreground uppercase tracking-wider">Provider</th>
                  <th className="text-right px-2.5 py-1.5 font-semibold text-muted-foreground uppercase tracking-wider">Event ID</th>
                  <th className="text-left px-2.5 py-1.5 font-semibold text-muted-foreground uppercase tracking-wider">Level</th>
                  <th className="text-left px-2.5 py-1.5 font-semibold text-muted-foreground uppercase tracking-wider">Message</th>
                </tr>
              </thead>
              <tbody>
                {data.events!.map((event, i) => (
                  <tr key={i} className="border-b border-border/40 last:border-0 align-top">
                    <td className="px-2.5 py-1.5 font-mono text-muted-foreground whitespace-nowrap">{event.timeCreated}</td>
                    <td className="px-2.5 py-1.5 text-foreground">{event.provider}</td>
                    <td className="px-2.5 py-1.5 text-right font-mono tabular-nums text-muted-foreground">{event.eventId ?? '—'}</td>
                    <td className="px-2.5 py-1.5 text-muted-foreground">{event.level || '—'}</td>
                    <td className="px-2.5 py-1.5 text-foreground max-w-[320px]">{event.message}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    );
  }

  // Default: pretty JSON or plain text viewer.
  return (
    <pre className="text-[11px] font-mono text-foreground bg-muted/40 border border-border rounded-md p-3 overflow-x-auto max-h-80 overflow-y-auto whitespace-pre-wrap break-all">
      {isJson && parsed !== null ? JSON.stringify(parsed, null, 2) : artifact.content}
    </pre>
  );
}

interface EvidenceDetailDialogProps {
  evidenceId: string | null;
  open: boolean;
  onClose: () => void;
  /** Called after a successful integrity verification so lists can refresh. */
  onVerified?: () => void;
}

export function EvidenceDetailDialog({ evidenceId, open, onClose, onVerified }: EvidenceDetailDialogProps) {
  const [detail, setDetail] = useState<EvidenceDetail | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [artifact, setArtifact] = useState<ArtifactContent | null>(null);
  const [artifactError, setArtifactError] = useState<string | null>(null);
  const [artifactLoaded, setArtifactLoaded] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [verifyMessage, setVerifyMessage] = useState<string | null>(null);

  const loadDetail = useCallback(async (id: string) => {
    setLoading(true);
    setError(null);
    try {
      setDetail(await getEvidenceDetail(id));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load evidence details');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!open || !evidenceId) return;
    setDetail(null);
    setArtifact(null);
    setArtifactError(null);
    setArtifactLoaded(false);
    setVerifyMessage(null);
    void loadDetail(evidenceId);
  }, [open, evidenceId, loadDetail]);

  const loadArtifact = useCallback(async (id: string) => {
    setArtifactLoaded(true);
    setArtifactError(null);
    try {
      setArtifact(await getEvidenceArtifact(id));
    } catch (err) {
      setArtifact(null);
      setArtifactError(err instanceof Error ? err.message : 'Artifact could not be loaded');
    }
  }, []);

  const handleTabChange = (tab: string) => {
    if (tab === 'artifact' && !artifactLoaded && detail && detail.hasArtifact) {
      void loadArtifact(detail.id);
    }
  };

  const handleVerify = async () => {
    if (!detail) return;
    setVerifying(true);
    setVerifyMessage(null);
    try {
      const result = await verifyEvidenceIntegrity(detail.id);
      setVerifyMessage(result.message);
      await loadDetail(detail.id);
      onVerified?.();
    } catch (err) {
      setVerifyMessage(err instanceof Error ? err.message : 'Verification failed to run');
    } finally {
      setVerifying(false);
    }
  };

  const item: EvidenceItem | null = detail;

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Fingerprint className="size-5 text-primary" />
            {item ? (
              <>
                <span className="font-mono">{item.id}</span>
                <span className="text-muted-foreground font-normal">—</span>
                <span>{TYPE_LABELS[item.type] ?? item.type}</span>
              </>
            ) : (
              'Evidence Details'
            )}
          </DialogTitle>
          <DialogDescription>Evidence record, actual artifact, and chain of custody</DialogDescription>
        </DialogHeader>

        {loading && <p className="py-10 text-center text-sm text-muted-foreground">Loading evidence…</p>}
        {!loading && error && <p className="py-10 text-center text-sm text-critical">{error}</p>}

        {!loading && !error && item && (
          <Tabs defaultValue="overview" onValueChange={handleTabChange}>
            <TabsList className="bg-muted/40 border border-border h-9 p-1 w-full justify-start">
              <TabsTrigger value="overview" className="text-xs data-[state=active]:bg-primary/10 data-[state=active]:text-primary">
                Overview
              </TabsTrigger>
              <TabsTrigger value="artifact" className="text-xs data-[state=active]:bg-primary/10 data-[state=active]:text-primary">
                Artifact
              </TabsTrigger>
              <TabsTrigger value="custody" className="text-xs data-[state=active]:bg-primary/10 data-[state=active]:text-primary">
                Chain of Custody
              </TabsTrigger>
            </TabsList>

            {/* ── Overview ── */}
            <TabsContent value="overview" className="space-y-4 mt-3">
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-x-4 gap-y-3">
                <Field label="Evidence ID" mono>{item.id}</Field>
                <Field label="Incident ID" mono>{item.incidentId}</Field>
                <Field label="Type">{TYPE_LABELS[item.type] ?? item.type}</Field>
                <Field label="Source Endpoint" mono>{item.source}</Field>
                <Field label="Artifact File" mono>{item.artifactName || 'Not captured'}</Field>
                <Field label="Size">{item.sizeBytes ? `${item.sizeBytes} B (${item.size})` : item.size || '—'}</Field>
                <Field label="Collected At" mono>{formatExact(item.collectedAt)}</Field>
                <Field label="Collected By">{item.collectedBy || 'Not captured'}</Field>
                <Field label="Collection Method">
                  <span className={cn(
                    'inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider',
                    item.collectionMethod === 'automated'
                      ? 'bg-info/10 text-info border border-info/30'
                      : 'bg-primary/10 text-primary border border-primary/30',
                  )}>
                    {item.collectionMethod}
                  </span>
                </Field>
              </div>

              <div className="space-y-1.5">
                <div className="flex items-center gap-2">
                  <IntegrityBadge integrity={item.integrity} withTooltip />
                  <Button
                    variant="outline"
                    size="sm"
                    className="h-7 text-xs gap-1.5"
                    disabled={verifying}
                    onClick={() => void handleVerify()}
                  >
                    {verifying
                      ? <Loader2 className="size-3.5 animate-spin" />
                      : <ShieldCheck className="size-3.5" />}
                    Verify Integrity
                  </Button>
                  <CopyButton value={item.sha256} label="Copy SHA-256" />
                </div>
                <p className="text-[11px] text-muted-foreground">
                  {verifyMessage ??
                    'Integrity verified — the stored artifact matches its recorded SHA-256 hash.'}
                </p>
                <p className="text-[11px] font-mono text-muted-foreground break-all bg-muted/40 rounded px-2 py-1.5 border border-border/60">
                  {item.sha256 || 'Not captured'}
                </p>
              </div>

              <div>
                <p className="text-[10px] text-muted-foreground uppercase tracking-wider font-medium">Description</p>
                <p className="text-xs text-foreground mt-0.5">{item.description}</p>
              </div>
            </TabsContent>

            {/* ── Artifact ── */}
            <TabsContent value="artifact" className="mt-3">
              {!item.hasArtifact ? (
                <p className="text-xs text-muted-foreground flex items-start gap-2 p-3 rounded-md border border-border bg-muted/30">
                  <CircleAlert className="size-4 text-warning mt-0.5 flex-shrink-0" />
                  Artifact unavailable for legacy record — no stored file is referenced by this evidence.
                </p>
              ) : !artifactLoaded ? (
                <p className="py-8 text-center text-sm text-muted-foreground">Open the Artifact tab to load the stored artifact.</p>
              ) : artifactError ? (
                <p className="text-xs text-critical flex items-start gap-2 p-3 rounded-md border border-critical/30 bg-critical/[0.06]">
                  <CircleAlert className="size-4 mt-0.5 flex-shrink-0" />
                  {artifactError}
                </p>
              ) : artifact ? (
                <div className="space-y-2">
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <p className="text-xs font-mono text-foreground">
                      {artifact.artifactName}
                      <span className="text-muted-foreground ml-2">({artifact.mimeType})</span>
                    </p>
                    {!artifact.binaryUnsupported && (
                      <CopyButton value={artifact.content} label="Copy artifact text" />
                    )}
                  </div>
                  <ArtifactView artifact={artifact} evidenceType={item.type} />
                  <p className="text-[10px] text-muted-foreground">
                    Artifacts are displayed read-only and are never executed.
                  </p>
                </div>
              ) : null}
            </TabsContent>

            {/* ── Chain of custody ── */}
            <TabsContent value="custody" className="mt-3">
              {(detail?.custody.length ?? 0) === 0 ? (
                <p className="text-xs text-muted-foreground flex items-start gap-2 p-3 rounded-md border border-border bg-muted/30">
                  <History className="size-4 mt-0.5 flex-shrink-0" />
                  No custody history recorded for this legacy artifact. Run “Verify Integrity” to establish a verifiable record.
                </p>
              ) : (
                <div className="relative space-y-0">
                  {detail!.custody.map((entry, idx) => {
                    const isLast = idx === detail!.custody.length - 1;
                    return (
                      <div key={idx} className="flex gap-3 pb-4 relative last:pb-0">
                        {!isLast && <div className="absolute left-[5px] top-4 bottom-0 w-px bg-border" />}
                        <span className="relative mt-1.5 size-2.5 rounded-full bg-primary border-2 border-background flex-shrink-0 z-10" />
                        <div className="min-w-0">
                          <p className="text-xs font-semibold text-foreground">{entry.action}</p>
                          <p className="text-[11px] text-muted-foreground mt-0.5 font-mono">
                            {formatExact(entry.timestamp)}
                            {entry.actor && <span className="font-sans"> — {entry.actor}</span>}
                          </p>
                          {entry.detail && (
                            <p className="text-[11px] text-muted-foreground mt-0.5 break-all font-mono">{entry.detail}</p>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </TabsContent>
          </Tabs>
        )}
      </DialogContent>
    </Dialog>
  );
}

export { TYPE_LABELS as EVIDENCE_TYPE_LABELS, formatExact as formatExactTimestamp };
